<?php

declare(strict_types=1);

namespace PrimeDefender;

final class PrimeDefenderSettings
{
    private const MODE_KEYS = [
        'authBypassMode',
        'suspiciousRequestMode',
        'suspiciousUaMode',
        'sqliMode',
        'xssMode',
        'pathTraversalMode',
        'cmdInjectionMode',
        'fileInclusionMode',
        'ddosMode',
        'bruteForceMode',
        'scannerMode',
        'botActivityMode',
    ];

    private static ?PrimeDefenderSettings $cached = null;

    public readonly string $bridgeUrl;
    public readonly string $apiKey;
    public readonly string $siteId;
    public readonly float $siteLat;
    public readonly float $siteLon;
    public readonly string $siteRegionLabel;
    public readonly string $privateSourceLabel;
    public readonly int $bodyCapBytes;
    public readonly int $geoipTtlSeconds;
    public readonly float $geoipTimeoutSeconds;
    public readonly float $bridgeTimeoutSeconds;
    public readonly int $floodWindowSeconds;
    public readonly int $floodMaxRequests;
    /** @var list<string> */
    public readonly array $floodExemptPaths;
    public readonly int $bruteForceWindowSeconds;
    public readonly int $bruteForceMaxAttempts;
    public readonly int $botWindowSeconds;
    public readonly int $botMaxRequests;
    public readonly int $scannerWindowSeconds;
    public readonly int $scannerMaxRequests;
    public readonly int $suspiciousRequestWindowSeconds;
    public readonly int $suspiciousRequestMaxRequests;
    public readonly bool $blockCurlUa;
    public readonly string $authBypassMode;
    public readonly string $suspiciousRequestMode;
    public readonly string $suspiciousUaMode;
    public readonly string $sqliMode;
    public readonly string $xssMode;
    public readonly string $pathTraversalMode;
    public readonly string $cmdInjectionMode;
    public readonly string $fileInclusionMode;
    public readonly string $ddosMode;
    public readonly string $bruteForceMode;
    public readonly string $scannerMode;
    public readonly string $botActivityMode;
    public readonly bool $ddosEnabled;
    public readonly bool $bruteForceEnabled;
    public readonly bool $scannerEnabled;
    public readonly bool $botActivityEnabled;
    public readonly bool $suspiciousRequestEnabled;
    public readonly bool $suspiciousUaEnabled;
    public readonly bool $sqliEnabled;
    public readonly bool $xssEnabled;
    public readonly bool $pathTraversalEnabled;
    public readonly bool $cmdInjectionEnabled;
    public readonly bool $fileInclusionEnabled;
    public readonly bool $authBypassEnabled;
    public readonly bool $debug;
    public readonly int $maxEncodingLayers;

  /**
   * @param array<string, mixed> $init
   */
    public function __construct(array $init)
    {
        $this->bridgeUrl = (string) ($init['bridgeUrl'] ?? '');
        $this->apiKey = (string) ($init['apiKey'] ?? '');
        $this->siteId = (string) ($init['siteId'] ?? '');
        $this->siteLat = (float) ($init['siteLat'] ?? 0.0);
        $this->siteLon = (float) ($init['siteLon'] ?? 0.0);
        $this->siteRegionLabel = (string) ($init['siteRegionLabel'] ?? '');
        $this->privateSourceLabel = (string) ($init['privateSourceLabel'] ?? '');
        $this->bodyCapBytes = (int) ($init['bodyCapBytes'] ?? 16384);
        $this->geoipTtlSeconds = (int) ($init['geoipTtlSeconds'] ?? 3600);
        $this->geoipTimeoutSeconds = (float) ($init['geoipTimeoutSeconds'] ?? 2.5);
        $this->bridgeTimeoutSeconds = (float) ($init['bridgeTimeoutSeconds'] ?? 3.0);
        $this->floodWindowSeconds = (int) ($init['floodWindowSeconds'] ?? 10);
        $this->floodMaxRequests = (int) ($init['floodMaxRequests'] ?? 90);
        $this->floodExemptPaths = $init['floodExemptPaths'] ?? [];
        $this->bruteForceWindowSeconds = (int) ($init['bruteForceWindowSeconds'] ?? 60);
        $this->bruteForceMaxAttempts = (int) ($init['bruteForceMaxAttempts'] ?? 8);
        $this->botWindowSeconds = (int) ($init['botWindowSeconds'] ?? 30);
        $this->botMaxRequests = (int) ($init['botMaxRequests'] ?? 35);
        $this->scannerWindowSeconds = (int) ($init['scannerWindowSeconds'] ?? 60);
        $this->scannerMaxRequests = (int) ($init['scannerMaxRequests'] ?? 10);
        $this->suspiciousRequestWindowSeconds = (int) ($init['suspiciousRequestWindowSeconds'] ?? 60);
        $this->suspiciousRequestMaxRequests = (int) ($init['suspiciousRequestMaxRequests'] ?? 6);
        $this->blockCurlUa = (bool) ($init['blockCurlUa'] ?? true);
        $this->authBypassMode = (string) ($init['authBypassMode'] ?? 'block');
        $this->suspiciousRequestMode = (string) ($init['suspiciousRequestMode'] ?? 'block');
        $this->suspiciousUaMode = (string) ($init['suspiciousUaMode'] ?? 'block');
        $this->sqliMode = (string) ($init['sqliMode'] ?? 'block');
        $this->xssMode = (string) ($init['xssMode'] ?? 'block');
        $this->pathTraversalMode = (string) ($init['pathTraversalMode'] ?? 'block');
        $this->cmdInjectionMode = (string) ($init['cmdInjectionMode'] ?? 'block');
        $this->fileInclusionMode = (string) ($init['fileInclusionMode'] ?? 'block');
        $this->ddosMode = (string) ($init['ddosMode'] ?? 'block');
        $this->bruteForceMode = (string) ($init['bruteForceMode'] ?? 'block');
        $this->scannerMode = (string) ($init['scannerMode'] ?? 'block');
        $this->botActivityMode = (string) ($init['botActivityMode'] ?? 'block');
        $this->ddosEnabled = (bool) ($init['ddosEnabled'] ?? true);
        $this->bruteForceEnabled = (bool) ($init['bruteForceEnabled'] ?? true);
        $this->scannerEnabled = (bool) ($init['scannerEnabled'] ?? true);
        $this->botActivityEnabled = (bool) ($init['botActivityEnabled'] ?? true);
        $this->suspiciousRequestEnabled = (bool) ($init['suspiciousRequestEnabled'] ?? true);
        $this->suspiciousUaEnabled = (bool) ($init['suspiciousUaEnabled'] ?? true);
        $this->sqliEnabled = (bool) ($init['sqliEnabled'] ?? true);
        $this->xssEnabled = (bool) ($init['xssEnabled'] ?? true);
        $this->pathTraversalEnabled = (bool) ($init['pathTraversalEnabled'] ?? true);
        $this->cmdInjectionEnabled = (bool) ($init['cmdInjectionEnabled'] ?? true);
        $this->fileInclusionEnabled = (bool) ($init['fileInclusionEnabled'] ?? true);
        $this->authBypassEnabled = (bool) ($init['authBypassEnabled'] ?? true);
        $this->debug = (bool) ($init['debug'] ?? false);
        $this->maxEncodingLayers = (int) ($init['maxEncodingLayers'] ?? 3);
    }

    /** @return list<string> */
  public function getObserveOnlyDetections(): array
    {
        $mapping = [
            'ddos' => $this->ddosMode,
            'brute_force' => $this->bruteForceMode,
            'scanner' => $this->scannerMode,
            'bot_activity' => $this->botActivityMode,
            'suspicious_request' => $this->suspiciousRequestMode,
            'suspicious_ua' => $this->suspiciousUaMode,
            'sqli' => $this->sqliMode,
            'xss' => $this->xssMode,
            'path_traversal' => $this->pathTraversalMode,
            'cmd_injection' => $this->cmdInjectionMode,
            'file_inclusion' => $this->fileInclusionMode,
            'auth_bypass' => $this->authBypassMode,
        ];
        $out = [];
        foreach ($mapping as $key => $mode) {
            if ($mode === 'observe') {
                $out[] = $key;
            }
        }
        return $out;
    }

    public function blocksDetection(string $key): bool
    {
        return !in_array($key, $this->getObserveOnlyDetections(), true);
    }

    public function getResolvedBridgeUrl(): string
    {
        $raw = trim($this->bridgeUrl);
        if ($raw === '') {
            return $raw;
        }
        $parsed = parse_url($raw);
        if ($parsed !== false && isset($parsed['scheme'])) {
            $path = $parsed['path'] ?? '';
            if ($path === '' || $path === '/') {
                return rtrim($raw, '/') . '/ingest';
            }
            return $raw;
        }
        $trimmed = rtrim($raw, '/');
        return str_ends_with($trimmed, '/ingest') ? $trimmed : $trimmed . '/ingest';
    }

    public function isEnabled(): bool
    {
        return $this->bridgeUrl !== '' && $this->apiKey !== '' && $this->siteId !== '';
    }

    /**
     * @param array<string, mixed> $overrides
     */
    public static function fromEnv(array $overrides = []): self
    {
        $data = [
            'bridgeUrl' => self::envStr('PRIMEDEFENDER_BRIDGE_URL'),
            'apiKey' => self::envStr('PRIMEDEFENDER_API_KEY'),
            'siteId' => self::envStr('PRIMEDEFENDER_SITE_ID', 'primestudio-api'),
            'siteLat' => self::envFloat('PRIMEDEFENDER_SITE_LAT', -8.6705),
            'siteLon' => self::envFloat('PRIMEDEFENDER_SITE_LON', 115.2126),
            'siteRegionLabel' => self::envStr('PRIMEDEFENDER_SITE_REGION_LABEL', 'Indonesia, Bali') ?: 'Indonesia, Bali',
            'privateSourceLabel' => self::envStr('PRIMEDEFENDER_PRIVATE_SOURCE_LABEL', 'Local / private network')
                ?: 'Local / private network',
            'bodyCapBytes' => self::envInt('PRIMEDEFENDER_BODY_CAP_BYTES', 16384),
            'geoipTtlSeconds' => self::envInt('PRIMEDEFENDER_GEOIP_TTL_SECONDS', 3600),
            'geoipTimeoutSeconds' => self::envFloat('PRIMEDEFENDER_GEOIP_TIMEOUT_SECONDS', 2.5),
            'bridgeTimeoutSeconds' => self::envFloat('PRIMEDEFENDER_BRIDGE_TIMEOUT_SECONDS', 3.0),
            'floodWindowSeconds' => self::envInt('PRIMEDEFENDER_FLOOD_WINDOW_SECONDS', 10),
            'floodMaxRequests' => self::envInt('PRIMEDEFENDER_FLOOD_MAX_REQUESTS', 90),
            'floodExemptPaths' => self::floodExemptPathsFromEnv(),
            'bruteForceWindowSeconds' => self::envInt('PRIMEDEFENDER_BRUTE_WINDOW_SECONDS', 60),
            'bruteForceMaxAttempts' => self::envInt('PRIMEDEFENDER_BRUTE_MAX_ATTEMPTS', 8),
            'botWindowSeconds' => self::envInt('PRIMEDEFENDER_BOT_WINDOW_SECONDS', 30),
            'botMaxRequests' => self::envInt('PRIMEDEFENDER_BOT_MAX_REQUESTS', 35),
            'scannerWindowSeconds' => self::envInt('PRIMEDEFENDER_SCANNER_WINDOW_SECONDS', 60),
            'scannerMaxRequests' => self::envInt('PRIMEDEFENDER_SCANNER_MAX_REQUESTS', 10),
            'suspiciousRequestWindowSeconds' => self::envInt('PRIMEDEFENDER_SUSPICIOUS_WINDOW_SECONDS', 60),
            'suspiciousRequestMaxRequests' => self::envInt('PRIMEDEFENDER_SUSPICIOUS_MAX_REQUESTS', 6),
            'blockCurlUa' => self::envBool('PRIMEDEFENDER_BLOCK_CURL_UA', true),
            'authBypassMode' => self::envMode('PRIMEDEFENDER_AUTH_BYPASS_MODE', 'block'),
            'suspiciousRequestMode' => self::envMode('PRIMEDEFENDER_SUSPICIOUS_REQUEST_MODE', 'block'),
            'suspiciousUaMode' => self::envMode('PRIMEDEFENDER_SUSPICIOUS_UA_MODE', 'block'),
            'sqliMode' => self::envMode('PRIMEDEFENDER_SQLI_MODE', 'block'),
            'xssMode' => self::envMode('PRIMEDEFENDER_XSS_MODE', 'block'),
            'pathTraversalMode' => self::envMode('PRIMEDEFENDER_PATH_TRAVERSAL_MODE', 'block'),
            'cmdInjectionMode' => self::envMode('PRIMEDEFENDER_CMD_INJECTION_MODE', 'block'),
            'fileInclusionMode' => self::envMode('PRIMEDEFENDER_FILE_INCLUSION_MODE', 'block'),
            'ddosMode' => self::envMode('PRIMEDEFENDER_DDOS_MODE', 'block'),
            'bruteForceMode' => self::envMode('PRIMEDEFENDER_BRUTE_FORCE_MODE', 'block'),
            'scannerMode' => self::envMode('PRIMEDEFENDER_SCANNER_MODE', 'block'),
            'botActivityMode' => self::envMode('PRIMEDEFENDER_BOT_ACTIVITY_MODE', 'block'),
            'ddosEnabled' => self::envBool('PRIMEDEFENDER_DDOS_ENABLED', true),
            'bruteForceEnabled' => self::envBool('PRIMEDEFENDER_BRUTE_FORCE_ENABLED', true),
            'scannerEnabled' => self::envBool('PRIMEDEFENDER_SCANNER_ENABLED', true),
            'botActivityEnabled' => self::envBool('PRIMEDEFENDER_BOT_ACTIVITY_ENABLED', true),
            'suspiciousRequestEnabled' => self::envBool('PRIMEDEFENDER_SUSPICIOUS_REQUEST_ENABLED', true),
            'suspiciousUaEnabled' => self::envBool('PRIMEDEFENDER_SUSPICIOUS_UA_ENABLED', true),
            'sqliEnabled' => self::envBool('PRIMEDEFENDER_SQLI_ENABLED', true),
            'xssEnabled' => self::envBool('PRIMEDEFENDER_XSS_ENABLED', true),
            'pathTraversalEnabled' => self::envBool('PRIMEDEFENDER_PATH_TRAVERSAL_ENABLED', true),
            'cmdInjectionEnabled' => self::envBool('PRIMEDEFENDER_CMD_INJECTION_ENABLED', true),
            'fileInclusionEnabled' => self::envBool('PRIMEDEFENDER_FILE_INCLUSION_ENABLED', true),
            'authBypassEnabled' => self::envBool('PRIMEDEFENDER_AUTH_BYPASS_ENABLED', true),
            'debug' => self::envBool('PRIMEDEFENDER_DEBUG', false),
            'maxEncodingLayers' => self::envInt('PRIMEDEFENDER_MAX_ENCODING_LAYERS', 3),
        ];

        $aliasMap = ['siteLabel' => 'siteRegionLabel'];

        foreach ($overrides as $key => $value) {
            if ($value === null) {
                continue;
            }
            $target = $aliasMap[$key] ?? $key;
            if (!array_key_exists($target, $data)) {
                continue;
            }
            if (in_array($target, self::MODE_KEYS, true)) {
                $data[$target] = self::asMode($value, (string) $data[$target]);
                continue;
            }
            if ($target === 'floodExemptPaths') {
                if (is_string($value)) {
                    $data['floodExemptPaths'] = trim($value) !== '' ? self::parseCsvPaths($value) : [];
                } elseif (is_array($value)) {
                    $data['floodExemptPaths'] = array_map(
                        static fn ($p) => str_starts_with((string) $p, '/') ? (string) $p : '/' . $p,
                        $value,
                    );
                }
                continue;
            }
            $data[$target] = $value;
        }

        return new self($data);
    }

    public static function loadSettings(): self
    {
        if (self::$cached === null) {
            self::$cached = self::fromEnv();
        }
        return self::$cached;
    }

    public static function clearSettingsCache(): void
    {
        self::$cached = null;
    }

    private static function envStr(string $key, string $fallback = ''): string
    {
        $raw = self::envRaw($key);
        if ($raw === null) {
            return $fallback;
        }
        return trim($raw);
    }

    private static function envFloat(string $key, float $fallback): float
    {
        $raw = self::envRaw($key);
        if ($raw === null || $raw === '') {
            return $fallback;
        }
        $n = (float) $raw;
        return is_finite($n) ? $n : $fallback;
    }

    private static function envInt(string $key, int $fallback): int
    {
        $raw = self::envRaw($key);
        if ($raw === null || $raw === '') {
            return $fallback;
        }
        $n = (int) $raw;
        return is_finite((float) $raw) ? $n : $fallback;
    }

    private static function envBool(string $key, bool $fallback = false): bool
    {
        $raw = self::envRaw($key);
        if ($raw === null || $raw === '') {
            return $fallback;
        }
        return in_array(strtolower($raw), ['1', 'true', 'yes', 'on'], true);
    }

    private static function envMode(string $key, string $fallback): string
    {
        $raw = strtolower(trim(self::envRaw($key) ?? ''));
        if ($raw === 'observe' || $raw === 'block') {
            return $raw;
        }
        return $fallback;
    }

    private static function envRaw(string $key): ?string
    {
        $value = $_ENV[$key] ?? $_SERVER[$key] ?? getenv($key);
        if ($value === false || $value === null) {
            return null;
        }
        return (string) $value;
    }

    /** @return list<string> */
    private static function parseCsvPaths(string $raw): array
    {
        $out = [];
        foreach (explode(',', $raw) as $part) {
            $trimmed = trim($part);
            if ($trimmed === '') {
                continue;
            }
            $out[] = str_starts_with($trimmed, '/') ? $trimmed : '/' . $trimmed;
        }
        return $out;
    }

    /** @return list<string> */
    private static function floodExemptPathsFromEnv(): array
    {
        $raw = self::envRaw('PRIMEDEFENDER_FLOOD_EXEMPT_PATHS');
        if ($raw === null) {
            return ['/health'];
        }
        if (trim($raw) === '') {
            return [];
        }
        return self::parseCsvPaths($raw);
    }

    private static function asMode(mixed $value, string $fallback): string
    {
        $v = strtolower((string) $value);
        if ($v === 'observe' || $v === 'block') {
            return $v;
        }
        return $fallback;
    }
}
