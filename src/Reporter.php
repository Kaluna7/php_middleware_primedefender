<?php

declare(strict_types=1);

namespace PrimeDefender;

final class Reporter
{
    /**
     * @param array<string, mixed> $meta
     */
    public static function reportIncident(
        Config $settings,
        Geo $geo,
        Detection $detection,
        array $meta,
    ): void {
        if (!$settings->isEnabled()) {
            if ($settings->debug) {
                error_log('PrimeDefender: skip bridge (set PRIMEDEFENDER_BRIDGE_URL, API_KEY, SITE_ID)');
            }
            return;
        }

        $url = $settings->getResolvedBridgeUrl();
        if ($settings->debug) {
            error_log('PrimeDefender: POST ' . $url . ' detection=' . $detection->name);
        }

        $clientIp = (string) ($meta['clientIp'] ?? '');
        [$ohLat, $ohLon, $ohLabel] = self::primeHeaderOverrides($meta);
        $hasCoordOverride = $ohLat !== null && $ohLon !== null;
        $hasLabelOverride = $ohLabel !== '';

        $geoLat = null;
        $geoLon = null;
        $geoLabel = null;
        $geoIsp = null;
        if (!$hasCoordOverride) {
            [$geoLat, $geoLon, $geoLabel, $geoIsp] = $geo->get($clientIp);
        }

        $attackerLat = $hasCoordOverride ? $ohLat : $geoLat;
        $attackerLon = $hasCoordOverride ? $ohLon : $geoLon;
        if ($attackerLat === null || $attackerLon === null) {
            $attackerLat = 0.0;
            $attackerLon = 0.0;
        }

        if ($hasLabelOverride) {
            $sourceLabel = $ohLabel;
        } elseif ($hasCoordOverride && !$hasLabelOverride) {
            $sourceLabel = sprintf('%.3f, %.3f', $attackerLat, $attackerLon);
        } elseif (Geo::isPrivateIp($clientIp)) {
            $sourceLabel = $settings->privateSourceLabel;
        } elseif ($geoLabel !== null && $geoLabel !== '') {
            $sourceLabel = $geoLabel;
        } else {
            $sourceLabel = 'Unknown location (' . $clientIp . ')';
        }

        $targetLabel = $detection->targetLabel ?? ($settings->siteId . ' · ' . $settings->siteRegionLabel);

        $payload = [
            'from' => ['lat' => (float) $attackerLat, 'lon' => (float) $attackerLon],
            'to' => ['lat' => (float) $settings->siteLat, 'lon' => (float) $settings->siteLon],
            'category' => $detection->category,
            'severity' => $detection->severity,
            'sourceLabel' => $sourceLabel,
            'targetLabel' => $targetLabel,
            'siteId' => $settings->siteId,
            'createdAt' => (int) round(microtime(true) * 1000),
            'blocked' => $detection->blocked,
            'action' => $detection->action,
            'path' => (string) ($meta['path'] ?? ''),
            'method' => (string) ($meta['method'] ?? ''),
            'attackerIp' => $clientIp,
            'userAgent' => (string) ($meta['userAgent'] ?? ''),
            'detection' => $detection->name,
            'requestId' => (string) ($meta['requestId'] ?? self::requestIdFromMeta($meta)),
            'forwardedFor' => self::headerValue($meta, 'x-forwarded-for'),
            'targetService' => $settings->siteId,
            'authStatus' => str_starts_with($detection->name, 'auth_bypass') ? 'bypass_attempt' : null,
            'detectType' => self::detectTypeFromName($detection->name),
            'detectConfidence' => is_numeric($meta['detectConfidence'] ?? null)
                ? (float) $meta['detectConfidence']
                : self::confidenceForDetection($detection->name, $detection->severity),
            'responseStatus' => $meta['responseStatus'] ?? null,
            'responseTimeMs' => $meta['responseTimeMs'] ?? null,
            'mitigation' => (string) ($meta['mitigation'] ?? $detection->action),
            'ipIntelIsp' => $meta['ipIntelIsp'] ?? $geoIsp,
            'requestsLast1m' => $meta['requestsLast1m'] ?? null,
        ];

        if ($detection->category === 'ddos') {
            $payload['ddos'] = ['vector' => 'application'];
        }

        try {
            $result = Ingest::postIncident(
                $url,
                $settings->apiKey,
                $payload,
                $settings->bridgeTimeoutSeconds,
            );
            $logMsg = sprintf(
                'PrimeDefender: bridge status=%d from=%s to=%s sourceLabel=%s targetLabel=%s detection=%s blocked=%s',
                $result['status'],
                json_encode($payload['from']),
                json_encode($payload['to']),
                json_encode($sourceLabel),
                json_encode($targetLabel),
                $detection->name,
                $detection->blocked ? 'true' : 'false',
            );
            if ($result['ok']) {
                error_log($logMsg);
            } else {
                error_log(
                    $logMsg . ' url=' . $url . ' body='
                    . json_encode(substr($result['bodyText'], 0, 800)),
                );
            }
        } catch (\Throwable $exc) {
            error_log('PrimeDefender: bridge error posting to ' . $url . ': ' . $exc->getMessage());
        }
    }

    /**
     * @param array<string, mixed> $meta
     * @return array{0: ?float, 1: ?float, 2: string}
     */
    public static function primeHeaderOverrides(array $meta): array
    {
        $headers = is_array($meta['headers'] ?? null) ? $meta['headers'] : [];
        $lat = self::parseHeaderFloat($headers['x-prime-source-lat'] ?? null);
        $lon = self::parseHeaderFloat($headers['x-prime-source-lon'] ?? null);
        $label = trim((string) ($headers['x-prime-source-label'] ?? ''));
        return [$lat, $lon, $label];
    }

    /**
     * @param array<string, mixed> $meta
     */
    public static function requestIdFromMeta(array $meta): string
    {
        $headers = is_array($meta['headers'] ?? null) ? $meta['headers'] : [];
        foreach (['x-request-id', 'x-correlation-id', 'cf-ray'] as $key) {
            $value = trim((string) ($headers[$key] ?? ''));
            if ($value !== '') {
                return substr($value, 0, 128);
            }
        }
        return bin2hex(random_bytes(16));
    }

    public static function detectTypeFromName(string $name): string
    {
        $idx = strpos($name, ':');
        return $idx === false ? $name : substr($name, 0, $idx);
    }

    public static function confidenceForDetection(string $name, string $severity): float
    {
        if (
            str_starts_with($name, 'cmd_injection')
            || str_starts_with($name, 'sqli')
            || str_starts_with($name, 'file_inclusion')
        ) {
            return 0.96;
        }
        if (str_starts_with($name, 'xss') || str_starts_with($name, 'path_traversal')) {
            return 0.91;
        }
        if (str_starts_with($name, 'auth_bypass')) {
            return 0.87;
        }
        if (
            str_starts_with($name, 'ddos')
            || str_starts_with($name, 'brute_force')
            || str_starts_with($name, 'scanner')
        ) {
            return 0.83;
        }
        if (str_starts_with($name, 'bot_activity')) {
            return 0.79;
        }
        if ($severity === 'critical') {
            return 0.93;
        }
        if ($severity === 'high') {
            return 0.86;
        }
        if ($severity === 'medium') {
            return 0.74;
        }
        return 0.61;
    }

  /**
   * @param array<string, mixed> $meta
   */
    private static function headerValue(array $meta, string $key): ?string
    {
        $headers = is_array($meta['headers'] ?? null) ? $meta['headers'] : [];
        $value = trim((string) ($headers[$key] ?? ''));
        return $value !== '' ? $value : null;
    }

    private static function parseHeaderFloat(mixed $raw): ?float
    {
        if ($raw === null || trim((string) $raw) === '') {
            return null;
        }
        $n = (float) trim((string) $raw);
        return is_finite($n) ? $n : null;
    }
}
