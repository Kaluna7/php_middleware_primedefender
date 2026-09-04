<?php

declare(strict_types=1);

namespace PrimeDefender;

use Psr\Http\Message\ResponseFactoryInterface;

final class PrimeDefender
{
    public const VERSION = '0.1.0';

    private static ?Config $guardSettings = null;
    private static ?Detectors $guardInspector = null;
    private static ?Geo $guardGeoip = null;
    private static ?RateLimit $guardRequestCounter = null;

    /**
     * @param array<string, mixed> $overrides
     */
    public static function middleware(
        ?Config $settings = null,
        ?ResponseFactoryInterface $responseFactory = null,
        array $overrides = [],
    ): Middleware {
        return new Middleware($settings, $responseFactory, $overrides);
    }

    /**
     * Plain PHP: inspect current request; if blocked, emit JSON and exit.
     *
     * Rate-limit state is kept in static process memory (shared across requests
     * in the same PHP-FPM / Apache worker).
     *
     * @param array<string, mixed> $overrides
     */
    public static function guard(array $overrides = []): void
    {
        $settings = self::resolveGuardSettings($overrides);

        $method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
        if ($method === 'OPTIONS' || !$settings->isEnabled()) {
            return;
        }

        $requestUri = $_SERVER['REQUEST_URI'] ?? '/';
        $hashPos = strpos($requestUri, '#');
        $withoutHash = $hashPos === false ? $requestUri : substr($requestUri, 0, $hashPos);
        $qPos = strpos($withoutHash, '?');
        if ($qPos === false) {
            $path = $withoutHash !== '' ? $withoutHash : '/';
            $query = '';
        } else {
            $path = substr($withoutHash, 0, $qPos) ?: '/';
            $query = substr($withoutHash, $qPos + 1);
        }

        if (SlarkCompat::shouldSkipInspection($method, $path)) {
            return;
        }

        $startedAt = microtime(true);
        $bodyCap = $settings->bodyCapBytes;
        $rawBody = file_get_contents('php://input');
        $bodySize = $rawBody !== false ? strlen($rawBody) : 0;
        $bodyText = $rawBody !== false ? substr($rawBody, 0, $bodyCap) : '';

        $headers = self::headersFromServer();
        $clientIp = self::extractClientIpFromServer($headers);
        if ($clientIp === '' || $clientIp === 'unknown') {
            return;
        }

        $decodedQuery = Detectors::unquotePlus($query);
        $decodedPath = Detectors::unquotePlus($path);
        $userAgent = $headers['user-agent'] ?? '';

        $inspector = self::guardInspector($settings);
        $geoip = self::guardGeoip($settings);
        $requestCounter = self::guardRequestCounter();

        $meta = [
            'method' => $method,
            'path' => $path,
            'decodedPath' => $decodedPath,
            'query' => $query,
            'decodedQuery' => $decodedQuery,
            'headers' => $headers,
            'userAgent' => $userAgent,
            'bodyText' => $bodyText,
            'bodySize' => $bodySize,
            'clientIp' => $clientIp,
            'requestId' => $headers['x-request-id']
                ?? $headers['x-correlation-id']
                ?? $headers['cf-ray']
                ?? null,
            'requestsLast1m' => $requestCounter->hit('req:' . $clientIp, 60),
        ];

        $detection = $inspector->inspect($meta);
        if ($detection === null) {
            return;
        }

        $meta['responseTimeMs'] = max(1, (int) round((microtime(true) - $startedAt) * 1000));
        $meta['mitigation'] = $detection->blocked && $detection->statusCode === 429
            ? 'temp_block'
            : ($detection->blocked ? 'request_block' : 'observe');

        if ($detection->blocked) {
            $meta['responseStatus'] = $detection->statusCode;
            Reporter::reportIncident($settings, $geoip, $detection, $meta);
            self::emitBlockResponse($detection);
            exit;
        }

        // Observe mode: report immediately (response status unknown until app finishes).
        $meta['responseStatus'] = null;
        Reporter::reportIncident($settings, $geoip, $detection, $meta);
    }

    /** Reset cached guard state (mainly for tests). */
    public static function clearGuardCache(): void
    {
        self::$guardSettings = null;
        self::$guardInspector = null;
        self::$guardGeoip = null;
        self::$guardRequestCounter = null;
    }

    /** @param array<string, mixed> $overrides */
    private static function resolveGuardSettings(array $overrides): Config
    {
        if ($overrides !== []) {
            $settings = Config::fromEnv($overrides);
            // Overrides imply a fresh inspector so rate limits stay tied to this config.
            self::$guardSettings = $settings;
            self::$guardInspector = null;
            self::$guardGeoip = null;
            return $settings;
        }

        if (self::$guardSettings === null) {
            self::$guardSettings = Config::loadSettings();
        }
        return self::$guardSettings;
    }

    private static function guardInspector(Config $settings): Detectors
    {
        if (self::$guardInspector === null) {
            $siteLabel = SlarkCompat::buildSiteLabel($settings->siteId, $settings->siteRegionLabel);
            self::$guardInspector = new Detectors($settings, $siteLabel);
        }
        return self::$guardInspector;
    }

    private static function guardGeoip(Config $settings): Geo
    {
        if (self::$guardGeoip === null) {
            self::$guardGeoip = new Geo($settings->geoipTtlSeconds, $settings->geoipTimeoutSeconds);
        }
        return self::$guardGeoip;
    }

    private static function guardRequestCounter(): RateLimit
    {
        if (self::$guardRequestCounter === null) {
            self::$guardRequestCounter = new RateLimit();
        }
        return self::$guardRequestCounter;
    }

    private static function emitBlockResponse(Detection $detection): void
    {
        $errorCode = $detection->statusCode === 429 ? 'rate_limited' : 'forbidden';
        $body = [
            'error' => $errorCode,
            'reason' => $detection->reason ?? $detection->detail,
        ];
        if ($detection->ruleId !== null) {
            $body['rule'] = $detection->ruleId;
        }

        if (!headers_sent()) {
            header('Content-Type: application/json; charset=utf-8');
            header('X-Slark-Detection: ' . $detection->name);
            if ($detection->retryAfterSec !== null) {
                header('Retry-After: ' . $detection->retryAfterSec);
            }
            http_response_code($detection->statusCode);
        }
        echo json_encode($body, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    }

    /** @return array<string, string> */
    private static function headersFromServer(): array
    {
        $out = [];
        foreach ($_SERVER as $key => $value) {
            if (!str_starts_with($key, 'HTTP_')) {
                continue;
            }
            $name = strtolower(str_replace('_', '-', substr($key, 5)));
            $out[$name] = (string) $value;
        }
        if (isset($_SERVER['CONTENT_TYPE'])) {
            $out['content-type'] = (string) $_SERVER['CONTENT_TYPE'];
        }
        if (isset($_SERVER['CONTENT_LENGTH'])) {
            $out['content-length'] = (string) $_SERVER['CONTENT_LENGTH'];
        }
        return $out;
    }

    /** @param array<string, string> $headers */
    private static function extractClientIpFromServer(array $headers): string
    {
        foreach (['cf-connecting-ip', 'x-real-ip'] as $name) {
            $value = $headers[$name] ?? '';
            if ($value !== '') {
                return Geo::stripV6Mapped(trim($value));
            }
        }
        $forwardedFor = $headers['x-forwarded-for'] ?? '';
        if ($forwardedFor !== '') {
            $first = trim(explode(',', $forwardedFor, 2)[0]);
            if ($first !== '') {
                return Geo::stripV6Mapped($first);
            }
        }
        $remote = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
        if ($remote !== '') {
            return Geo::stripV6Mapped(trim($remote));
        }
        return 'unknown';
    }
}
