<?php

declare(strict_types=1);

namespace PrimeDefender;

/** @phpstan-type GeoQuad array{0: ?float, 1: ?float, 2: ?string, 3: ?string} */
final class GeoIPCache
{
    /** @var array<string, array{expires: float, value: GeoQuad}> */
    private array $cache = [];

    public function __construct(
        public readonly int $ttlSeconds,
        public readonly float $timeoutSeconds,
    ) {
    }

    public static function stripV6Mapped(string $ip): string
    {
        return preg_replace('/^::ffff:/i', '', $ip) ?? $ip;
    }

    public static function isPrivateIp(string $ip): bool
    {
        $cleaned = self::stripV6Mapped(trim($ip));
        if ($cleaned === '') {
            return true;
        }

        if (str_contains($cleaned, ':')) {
            $lower = strtolower($cleaned);
            if ($lower === '::1' || $lower === '::') {
                return true;
            }
            if (str_starts_with($lower, 'fe80:')) {
                return true;
            }
            $first = explode(':', $lower, 2)[0];
            $n = (int) hexdec(substr(str_pad($first, 4, '0'), 0, 4));
            if (($n & 0xfe00) === 0xfc00) {
                return true;
            }
            return false;
        }

        $parts = array_map(static fn (string $p) => (int) $p, explode('.', $cleaned));
        if (count($parts) !== 4) {
            return true;
        }
        foreach ($parts as $n) {
            if ($n < 0 || $n > 255) {
                return true;
            }
        }
        [$a, $b] = $parts;
        if ($a === 10 || $a === 127 || $a === 0) {
            return true;
        }
        if ($a === 169 && $b === 254) {
            return true;
        }
        if ($a === 172 && $b >= 16 && $b <= 31) {
            return true;
        }
        if ($a === 192 && $b === 168) {
            return true;
        }
        return false;
    }

    public static function formatIpLocationLabel(
        ?string $country,
        ?string $regionName,
        ?string $city,
    ): ?string {
        if ($country === null || $country === '') {
            return null;
        }
        $second = $country === 'United States' ? ($regionName ?: $city) : ($city ?: $regionName);
        return $second ? $country . ', ' . $second : $country;
    }

    /** @return GeoQuad */
    public function get(string $ip): array
    {
        if ($ip === '' || self::isPrivateIp($ip)) {
            return [null, null, null, null];
        }

        $now = microtime(true);
        $cached = $this->cache[$ip] ?? null;
        if ($cached !== null && $cached['expires'] > $now) {
            return $cached['value'];
        }

        $quad = [null, null, null, null];

        $ipwho = $this->fetchJson('https://ipwho.is/' . rawurlencode($ip));
        if (is_array($ipwho) && ($ipwho['success'] ?? false) === true) {
            $conn = is_array($ipwho['connection'] ?? null) ? $ipwho['connection'] : [];
            $quad = [
                self::numOrNull($ipwho['latitude'] ?? null),
                self::numOrNull($ipwho['longitude'] ?? null),
                self::formatIpLocationLabel(
                    self::str($ipwho['country'] ?? null),
                    self::str($ipwho['region'] ?? null),
                    self::str($ipwho['city'] ?? null),
                ),
                self::str($conn['isp'] ?? null),
            ];
        }

        if ($quad[0] === null || $quad[1] === null) {
            $ipapi = $this->fetchJson('https://ipapi.co/' . rawurlencode($ip) . '/json/');
            if (
                is_array($ipapi)
                && isset($ipapi['latitude'], $ipapi['longitude'])
                && $ipapi['latitude'] !== null
                && $ipapi['longitude'] !== null
            ) {
                $quad = [
                    self::numOrNull($ipapi['latitude']),
                    self::numOrNull($ipapi['longitude']),
                    self::formatIpLocationLabel(
                        self::str($ipapi['country_name'] ?? null),
                        self::str($ipapi['region'] ?? null),
                        self::str($ipapi['city'] ?? null),
                    ),
                    self::str($ipapi['org'] ?? null),
                ];
            }
        }

        if ($quad[0] === null || $quad[1] === null) {
            $ipApi = $this->fetchJson(
                'http://ip-api.com/json/' . rawurlencode($ip)
                . '?fields=status,country,regionName,city,lat,lon,isp',
            );
            if (is_array($ipApi) && ($ipApi['status'] ?? '') === 'success') {
                $quad = [
                    self::numOrNull($ipApi['lat'] ?? null),
                    self::numOrNull($ipApi['lon'] ?? null),
                    self::formatIpLocationLabel(
                        self::str($ipApi['country'] ?? null),
                        self::str($ipApi['regionName'] ?? null),
                        self::str($ipApi['city'] ?? null),
                    ),
                    self::str($ipApi['isp'] ?? null),
                ];
            }
        }

        $this->cache[$ip] = ['expires' => $now + $this->ttlSeconds, 'value' => $quad];
        return $quad;
    }

    /** @return array<string, mixed>|null */
    private function fetchJson(string $url): ?array
    {
        $timeout = max(1, (int) ceil($this->timeoutSeconds));
        $body = null;

        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            if ($ch !== false) {
                curl_setopt_array($ch, [
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_TIMEOUT => $timeout,
                    CURLOPT_CONNECTTIMEOUT => $timeout,
                ]);
                $body = curl_exec($ch);
                curl_close($ch);
            }
        }

        if ($body === null || $body === false) {
            $context = stream_context_create([
                'http' => ['timeout' => $timeout],
            ]);
            $body = @file_get_contents($url, false, $context);
        }

        if ($body === false || $body === null || $body === '') {
            return null;
        }

        try {
            $decoded = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
            return is_array($decoded) ? $decoded : null;
        } catch (\JsonException) {
            return null;
        }
    }

    private static function numOrNull(mixed $v): ?float
    {
        if ($v === null) {
            return null;
        }
        $n = is_numeric($v) ? (float) $v : null;
        return $n !== null && is_finite($n) ? $n : null;
    }

    private static function str(mixed $v): ?string
    {
        if ($v === null) {
            return null;
        }
        $s = trim((string) $v);
        return $s !== '' ? $s : null;
    }
}
