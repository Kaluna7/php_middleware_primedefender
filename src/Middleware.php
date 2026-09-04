<?php

declare(strict_types=1);

namespace PrimeDefender;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class Middleware implements MiddlewareInterface
{
    private readonly ResponseFactoryInterface $responseFactory;
    private readonly Config $settings;
    private readonly Geo $geoip;
    private readonly Detectors $inspector;
    private readonly RateLimit $requestCounter;
    private readonly string $siteLabel;

    /**
     * @param array<string, mixed> $overrides
     */
    public function __construct(
        ?Config $settings = null,
        ?ResponseFactoryInterface $responseFactory = null,
        array $overrides = [],
    ) {
        if ($responseFactory === null) {
            throw new \InvalidArgumentException(
                'Middleware requires a Psr\Http\Message\ResponseFactoryInterface. '
                . 'Inject a response factory (e.g. from nyholm/psr7) or use PrimeDefender::guard() for plain PHP.',
            );
        }
        $this->responseFactory = $responseFactory;

        if ($settings !== null) {
            $this->settings = $settings;
        } elseif ($overrides !== []) {
            $this->settings = Config::fromEnv($overrides);
        } else {
            $this->settings = Config::loadSettings();
        }

        $this->siteLabel = SlarkCompat::buildSiteLabel(
            $this->settings->siteId,
            $this->settings->siteRegionLabel,
        );
        $this->geoip = new Geo(
            $this->settings->geoipTtlSeconds,
            $this->settings->geoipTimeoutSeconds,
        );
        $this->inspector = new Detectors($this->settings, $this->siteLabel);
        $this->requestCounter = new RateLimit();
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $method = strtoupper($request->getMethod());
        if ($method === 'OPTIONS' || !$this->settings->isEnabled()) {
            return $handler->handle($request);
        }

        $path = $request->getUri()->getPath() ?: '/';
        if (SlarkCompat::shouldSkipInspection($method, $path)) {
            return $handler->handle($request);
        }

        $startedAt = microtime(true);
        $bodyStream = $request->getBody();
        $bodyContents = $bodyStream->getContents();
        $bodySize = strlen($bodyContents);
        $bodyText = substr($bodyContents, 0, $this->settings->bodyCapBytes);
        if ($bodyStream->isSeekable()) {
            $bodyStream->rewind();
        }

        $headers = self::normalizeHeaders($request);
        $clientIp = self::extractClientIp($request, $headers);
        if ($clientIp === '' || $clientIp === 'unknown') {
            return $handler->handle($request);
        }

        $query = $request->getUri()->getQuery();
        $decodedQuery = Detectors::unquotePlus($query);
        $decodedPath = Detectors::unquotePlus($path);
        $userAgent = $headers['user-agent'] ?? '';

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
            'requestsLast1m' => $this->requestCounter->hit('req:' . $clientIp, 60),
        ];

        $detection = $this->inspector->inspect($meta);
        if ($detection === null) {
            return $handler->handle($request);
        }

        $meta['responseTimeMs'] = max(1, (int) round((microtime(true) - $startedAt) * 1000));
        $meta['mitigation'] = $detection->blocked && $detection->statusCode === 429
            ? 'temp_block'
            : ($detection->blocked ? 'request_block' : 'observe');

        if ($detection->blocked) {
            $meta['responseStatus'] = $detection->statusCode;
            Reporter::reportIncident($this->settings, $this->geoip, $detection, $meta);
            return self::buildBlockResponse($this->responseFactory, $detection);
        }

        $response = $handler->handle($request);
        $meta['responseStatus'] = $response->getStatusCode();
        $meta['mitigation'] = $response->getStatusCode() >= 400 ? 'observed_error' : $detection->action;
        Reporter::reportIncident($this->settings, $this->geoip, $detection, $meta);
        return $response;
    }

    public static function buildBlockResponse(
        ResponseFactoryInterface $responseFactory,
        Detection $detection,
    ): ResponseInterface {
        $errorCode = $detection->statusCode === 429 ? 'rate_limited' : 'forbidden';
        $body = [
            'error' => $errorCode,
            'reason' => $detection->reason ?? $detection->detail,
        ];
        if ($detection->ruleId !== null) {
            $body['rule'] = $detection->ruleId;
        }

        $response = $responseFactory
            ->createResponse($detection->statusCode)
            ->withHeader('Content-Type', 'application/json; charset=utf-8')
            ->withHeader('X-Slark-Detection', $detection->name);

        if ($detection->retryAfterSec !== null) {
            $response = $response->withHeader('Retry-After', (string) $detection->retryAfterSec);
        }

        $response->getBody()->write(json_encode($body, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR));
        return $response;
    }

    /** @return array<string, string> */
    private static function normalizeHeaders(ServerRequestInterface $request): array
    {
        $out = [];
        foreach ($request->getHeaders() as $key => $values) {
            $out[strtolower($key)] = implode(',', $values);
        }
        return $out;
    }

    /** @param array<string, string> $headers */
    private static function extractClientIp(ServerRequestInterface $request, array $headers): string
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
        $serverParams = $request->getServerParams();
        $remote = (string) ($serverParams['REMOTE_ADDR'] ?? '');
        if ($remote !== '') {
            return Geo::stripV6Mapped(trim($remote));
        }
        return 'unknown';
    }
}
