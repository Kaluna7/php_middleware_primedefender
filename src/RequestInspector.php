<?php

declare(strict_types=1);

namespace PrimeDefender;

final class RequestInspector
{
    private const SAMPLE_LIMIT = 8192;
    private const PATH_SAMPLE_LIMIT = 4096;

    /** @var array<string, true> */
    private readonly array $floodExemptNormalized;

    public readonly SlidingWindowLimiter $floodLimiter;
    public readonly SlidingWindowLimiter $bruteForceLimiter;
    public readonly SlidingWindowLimiter $botLimiter;
    public readonly SlidingWindowLimiter $scannerLimiter;
    public readonly SlidingWindowLimiter $suspiciousLimiter;

    public function __construct(
        public readonly PrimeDefenderSettings $settings,
        public readonly string $siteLabel,
    ) {
        $normalized = [];
        foreach ($settings->floodExemptPaths as $p) {
            $normalized[self::normalizePath($p)] = true;
        }
        $this->floodExemptNormalized = $normalized;
        $this->floodLimiter = new SlidingWindowLimiter();
        $this->bruteForceLimiter = new SlidingWindowLimiter();
        $this->botLimiter = new SlidingWindowLimiter();
        $this->scannerLimiter = new SlidingWindowLimiter();
        $this->suspiciousLimiter = new SlidingWindowLimiter();
    }

    public static function normalizePath(string $path): string
    {
        $p = explode('?', trim($path), 2)[0];
        if (!str_starts_with($p, '/')) {
            $p = '/' . $p;
        }
        $pl = rtrim(strtolower($p), '/');
        return $pl !== '' ? $pl : '/';
    }

    /** Percent-decode like Python urllib.parse.unquote (lenient; no + replacement). */
    public static function unquote(string $text): string
    {
        return preg_replace_callback(
            '/%([0-9A-Fa-f]{2})/',
            static fn (array $m) => chr((int) hexdec($m[1])),
            $text,
        ) ?? $text;
    }

    /** Percent-decode like Python urllib.parse.unquote_plus. */
    public static function unquotePlus(string $text): string
    {
        return self::unquote(str_replace('+', ' ', $text));
    }

    public static function decodeSample(string $text): string
    {
        try {
            return self::unquotePlus(str_replace('+', ' ', $text));
        } catch (\Throwable) {
            return $text;
        }
    }

    public static function decodeDeep(string $text, int $passes = 3): string
    {
        $out = $text;
        for ($i = 0; $i < $passes; $i++) {
            $nxt = self::decodeSample($out);
            if ($nxt === $out) {
                break;
            }
            $out = $nxt;
        }
        return $out;
    }

    public static function percentEncodingLayers(string $text): int
    {
        if ($text === '') {
            return 0;
        }
        $layers = 0;
        $cur = $text;
        for ($i = 0; $i < 128; $i++) {
            $nxt = self::unquote($cur);
            if ($nxt === $cur) {
                return $layers;
            }
            $layers++;
            $cur = $nxt;
        }
        return $layers;
    }

    public static function decodeDeepSample(string $text, int $sampleLimit = self::SAMPLE_LIMIT): string
    {
        $raw = substr($text, 0, $sampleLimit);
        $once = self::decodeSample($raw);
        $deep = self::decodeDeep($raw);
        return substr($raw . "\n" . $once . "\n" . $deep, 0, $sampleLimit);
    }

    /**
     * @param list<Rule> $rules
     */
    public static function runRules(string $text, array $rules, int $sampleLimit = self::SAMPLE_LIMIT): ?string
    {
        if ($text === '') {
            return null;
        }
        $haystack = self::decodeDeepSample($text, $sampleLimit);
        foreach ($rules as $rule) {
            if (preg_match($rule->pattern, $haystack) === 1) {
                return $rule->id;
            }
        }
        return null;
    }

    public static function pathMatches(string $actual, string $pattern): bool
    {
        if (str_ends_with($pattern, '*')) {
            return str_starts_with($actual, substr($pattern, 0, -1));
        }
        $p = explode('?', $pattern, 2)[0];
        $p = rtrim(strtolower($p !== '' ? $p : '/'), '/');
        $a = explode('?', $actual, 2)[0];
        $a = rtrim(strtolower($a !== '' ? $a : '/'), '/');
        return $a === $p || str_starts_with($a, $p . '/');
    }

    public static function detectScannerPath(string $path): ?string
    {
        $sample = substr($path, 0, self::PATH_SAMPLE_LIMIT);
        foreach (DetectionRules::getScannerPathRules() as $rule) {
            if (preg_match($rule->pattern, $sample) === 1) {
                return $rule->id;
            }
        }
        return null;
    }

    public static function detectSensitiveScanPath(string $path): bool
    {
        foreach (DetectionRules::getSensitiveScanPaths() as $marker) {
            if (self::pathMatches($path, $marker)) {
                return true;
            }
        }
        return false;
    }

    public static function detectSuspiciousUserAgent(string $ua, bool $blockCurl = true): ?string
    {
        if ($ua === '') {
            return null;
        }
        $rules = DetectionRules::getDefaultUaBlock();
        if (!$blockCurl) {
            $rules = array_values(array_filter($rules, static fn (Rule $r) => $r->id !== 'curl'));
        }
        foreach ($rules as $rule) {
            if (preg_match($rule->pattern, $ua) === 1) {
                return $rule->id;
            }
        }
        return null;
    }

    public static function matchesBrutePath(string $path, string $method): bool
    {
        if (!in_array($method, ['POST', 'GET', 'PUT', 'PATCH'], true)) {
            return false;
        }
        foreach (DetectionRules::getLoginPaths() as $loginPath) {
            if (self::pathMatches($path, $loginPath)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param array<string, mixed> $meta
     */
    public function inspect(array $meta): ?Detection
    {
        $ip = (string) ($meta['clientIp'] ?? '');
        $method = (string) ($meta['method'] ?? '');
        $path = (string) ($meta['path'] ?? '');
        $decodedPath = (string) ($meta['decodedPath'] ?? $path);
        $query = (string) ($meta['query'] ?? '');
        $decodedQuery = (string) ($meta['decodedQuery'] ?? $query);
        $bodyText = (string) ($meta['bodyText'] ?? '');
        $headers = is_array($meta['headers'] ?? null) ? $meta['headers'] : [];
        $ua = (string) ($meta['userAgent'] ?? '');
        $headerParts = [];
        foreach ($headers as $k => $v) {
            $headerParts[] = $k . ':' . $v;
        }
        $headerBlob = strtolower(implode(' ', $headerParts));
        $pathQuery = $decodedQuery !== '' ? $decodedPath . '?' . $decodedQuery : $decodedPath;
        $requestBlob = implode(
            "\n",
            array_filter([$pathQuery, $bodyText, $headerBlob, substr($ua, 0, 256)], static fn ($x) => $x !== ''),
        );

        $maxLayers = $this->settings->maxEncodingLayers;
        if ($maxLayers > 0) {
            $depth = max(
                self::percentEncodingLayers($query),
                self::percentEncodingLayers($bodyText),
            );
            if ($depth > $maxLayers) {
                return $this->decision('suspicious_request:excessive_encoding', [
                    'category' => 'intrusion',
                    'severity' => 'high',
                    'reason' => 'excessive_encoding',
                    'ruleId' => 'excessive_encoding',
                    'modeKey' => 'suspicious_request',
                    'statusCode' => 403,
                    'targetLabel' => $this->target($method, $path, 'Suspicious:excessive_encoding'),
                    'detail' => 'Nested percent-encoding exceeds allowed depth.',
                ]);
            }
        }

        $uaHit = $this->settings->suspiciousUaEnabled
            ? self::detectSuspiciousUserAgent($ua, $this->settings->blockCurlUa)
            : null;
        $uaKind = DetectionRules::classifyUaHit($uaHit);
        $botBehavior = $this->settings->botActivityEnabled
            ? DetectionRules::detectBotActivity([
                'ua' => $ua,
                'method' => $method,
                'headerBlob' => $headerBlob,
                'pathQuery' => $pathQuery,
            ])
            : null;
        $scannerPathHit = $this->settings->scannerEnabled ? self::detectScannerPath($decodedPath) : null;
        $sensitivePathHit = $this->settings->scannerEnabled
            ? self::detectSensitiveScanPath($decodedPath)
            : false;

        $onBrutePath = $this->settings->bruteForceEnabled && self::matchesBrutePath($decodedPath, $method);
        if ($onBrutePath) {
            [$allowed, , $retryAfter] = $this->bruteForceLimiter->recordWindow(
                'brute:' . $ip . ':' . $path,
                $this->settings->bruteForceWindowSeconds,
                $this->settings->bruteForceMaxAttempts,
            );
            if (!$allowed) {
                return $this->decision('brute_force', [
                    'category' => 'intrusion',
                    'severity' => 'high',
                    'reason' => 'brute_force_login',
                    'ruleId' => 'login_window',
                    'modeKey' => 'brute_force',
                    'statusCode' => 429,
                    'retryAfterSec' => $retryAfter,
                    'targetLabel' => $this->target($method, $path, 'BruteForce'),
                    'detail' => 'Brute force login pattern detected.',
                ]);
            }
        }

        if (!$onBrutePath && $this->settings->ddosEnabled && !$this->isFloodExempt($path)) {
            [$allowed, , $retryAfter] = $this->floodLimiter->recordWindow(
                $ip,
                $this->settings->floodWindowSeconds,
                $this->settings->floodMaxRequests,
            );
            if (!$allowed) {
                return $this->decision('ddos_flood', [
                    'category' => 'ddos',
                    'severity' => 'high',
                    'reason' => 'ddos_flood',
                    'ruleId' => 'global_window',
                    'modeKey' => 'ddos',
                    'statusCode' => 429,
                    'retryAfterSec' => $retryAfter,
                    'targetLabel' => $this->target($method, $path, 'flood'),
                    'detail' => 'Application flood limit exceeded.',
                ]);
            }
        }

        $scannerLike = $scannerPathHit !== null
            || $sensitivePathHit
            || $uaKind === 'scanner'
            || ($uaHit !== null && $uaKind === 'crawler');
        if ($scannerLike && $this->settings->scannerEnabled) {
            [$allowed, , $retryAfter] = $this->scannerLimiter->recordWindow(
                'scanner:' . $ip,
                $this->settings->scannerWindowSeconds,
                $this->settings->scannerMaxRequests,
            );
            if (!$allowed) {
                $ruleId = $scannerPathHit
                    ?? ($sensitivePathHit ? 'sensitive_path' : null)
                    ?? $uaHit
                    ?? 'probe_window';
                return $this->decision('scanner:' . $ruleId, [
                    'category' => 'botnet',
                    'severity' => 'medium',
                    'reason' => 'scanner_activity',
                    'ruleId' => $ruleId,
                    'modeKey' => 'scanner',
                    'statusCode' => 429,
                    'retryAfterSec' => $retryAfter,
                    'targetLabel' => $this->target($method, $path, 'Scanner:' . $ruleId),
                    'detail' => 'Scanner activity detected.',
                ]);
            }
        }

        $botSignal = $botBehavior !== null
            || $uaKind === 'bot_client'
            || $uaKind === 'automation'
            || $uaKind === 'crawler';
        if ($botSignal && $this->settings->botActivityEnabled) {
            $botRuleId = $botBehavior ?? $uaHit ?? 'behavior';
            [$allowed, , $retryAfter] = $this->botLimiter->recordWindow(
                'bot:' . $ip,
                $this->settings->botWindowSeconds,
                $this->settings->botMaxRequests,
            );
            if (!$allowed) {
                return $this->decision('bot_activity:' . $botRuleId, [
                    'category' => 'botnet',
                    'severity' => 'medium',
                    'reason' => 'bot_activity',
                    'ruleId' => $botRuleId,
                    'modeKey' => 'bot_activity',
                    'statusCode' => 429,
                    'retryAfterSec' => $retryAfter,
                    'targetLabel' => $this->target($method, $path, 'Bot:' . $botRuleId),
                    'detail' => 'Automated bot activity detected.',
                ]);
            }
        }

        if ($uaHit !== null && $this->settings->suspiciousUaEnabled) {
            $category = in_array($uaKind, ['scanner', 'automation', 'crawler'], true) ? 'botnet' : 'intrusion';
            $detectionName = in_array($uaKind, ['scanner', 'automation', 'crawler'], true)
                ? 'bot_activity:' . $uaHit
                : 'bad_ua:' . $uaHit;
            return $this->decision($detectionName, [
                'category' => $category,
                'severity' => 'medium',
                'reason' => 'suspicious_user_agent',
                'ruleId' => $uaHit,
                'modeKey' => 'suspicious_ua',
                'statusCode' => 403,
                'targetLabel' => $this->target($method, $path, 'UA:' . $uaHit),
                'detail' => 'Suspicious user agent blocked.',
            ]);
        }

        if (($scannerPathHit !== null || $sensitivePathHit) && $this->settings->scannerEnabled) {
            $ruleId = $scannerPathHit ?? 'sensitive_path';
            return $this->decision('scanner:' . $ruleId, [
                'category' => 'botnet',
                'severity' => 'medium',
                'reason' => 'scanner_path_probe',
                'ruleId' => $ruleId,
                'modeKey' => 'scanner',
                'statusCode' => 403,
                'targetLabel' => $this->target($method, $path, 'Scanner:' . $ruleId),
                'detail' => 'Scanner path probe blocked.',
            ]);
        }

        $signatureChecks = [
            [
                'prefix' => 'path_traversal',
                'rules' => DetectionRules::getPathTraversalRules(),
                'modeKey' => 'path_traversal',
                'reason' => 'path_traversal',
                'severity' => 'high',
                'enabled' => $this->settings->pathTraversalEnabled,
                'title' => 'PathTrav',
                'sample' => $pathQuery,
            ],
            [
                'prefix' => 'file_inclusion',
                'rules' => DetectionRules::getFileInclusionRules(),
                'modeKey' => 'file_inclusion',
                'reason' => 'file_inclusion',
                'severity' => 'high',
                'enabled' => $this->settings->fileInclusionEnabled,
                'title' => 'FileInclude',
                'sample' => $requestBlob,
            ],
            [
                'prefix' => 'cmd_injection',
                'rules' => DetectionRules::getCmdInjectionRules(),
                'modeKey' => 'cmd_injection',
                'reason' => 'command_injection',
                'severity' => 'critical',
                'enabled' => $this->settings->cmdInjectionEnabled,
                'title' => 'Cmd',
                'sample' => $requestBlob,
            ],
            [
                'prefix' => 'sqli',
                'rules' => DetectionRules::getSqliRules(),
                'modeKey' => 'sqli',
                'reason' => 'sql_injection_probe',
                'severity' => 'critical',
                'enabled' => $this->settings->sqliEnabled,
                'title' => 'SQLi',
                'sample' => $requestBlob,
            ],
            [
                'prefix' => 'xss',
                'rules' => DetectionRules::getXssRules(),
                'modeKey' => 'xss',
                'reason' => 'xss_probe',
                'severity' => 'high',
                'enabled' => $this->settings->xssEnabled,
                'title' => 'XSS',
                'sample' => $requestBlob,
            ],
        ];

        foreach ($signatureChecks as $check) {
            if (!$check['enabled']) {
                continue;
            }
            $hit = self::runRules($check['sample'], $check['rules']);
            if ($hit !== null) {
                $prefix = $check['prefix'];
                return $this->decision($prefix . ':' . $hit, [
                    'category' => 'intrusion',
                    'severity' => $check['severity'],
                    'reason' => $check['reason'],
                    'ruleId' => $hit,
                    'modeKey' => $check['modeKey'],
                    'statusCode' => 403,
                    'targetLabel' => $this->target($method, $path, $check['title'] . ':' . $hit),
                    'detail' => str_replace('_', ' ', $prefix) . ' signature matched.',
                ]);
            }
        }

        if ($this->settings->authBypassEnabled) {
            $authBlob = implode("\n", array_filter([$pathQuery, $headerBlob, $bodyText], static fn ($x) => $x !== ''));
            $authHit = self::runRules($authBlob, DetectionRules::getAuthBypassRules());
            if ($authHit !== null) {
                return $this->decision('auth_bypass:' . $authHit, [
                    'category' => 'intrusion',
                    'severity' => 'high',
                    'reason' => 'auth_bypass_probe',
                    'ruleId' => $authHit,
                    'modeKey' => 'auth_bypass',
                    'statusCode' => 403,
                    'targetLabel' => $this->target($method, $path, 'AuthBypass:' . $authHit),
                    'detail' => 'Authorization bypass probe observed.',
                ]);
            }
        }

        if ($this->settings->suspiciousRequestEnabled) {
            $suspiciousBlob = implode(
                "\n",
                array_filter([$pathQuery, $headerBlob, substr($ua, 0, 256)], static fn ($x) => $x !== ''),
            );
            $suspiciousHit = self::runRules($suspiciousBlob, DetectionRules::getSuspiciousRequestRules());
            if ($suspiciousHit !== null) {
                [$allowed, , $retryAfter] = $this->suspiciousLimiter->recordWindow(
                    'suspicious:' . $ip,
                    $this->settings->suspiciousRequestWindowSeconds,
                    $this->settings->suspiciousRequestMaxRequests,
                );
                if (!$allowed) {
                    return $this->decision('suspicious_request:' . $suspiciousHit, [
                        'category' => 'intrusion',
                        'severity' => 'medium',
                        'reason' => 'suspicious_request_burst',
                        'ruleId' => $suspiciousHit,
                        'modeKey' => 'suspicious_request',
                        'statusCode' => 429,
                        'retryAfterSec' => $retryAfter,
                        'targetLabel' => $this->target($method, $path, 'Suspicious:' . $suspiciousHit),
                        'detail' => 'Suspicious request burst detected.',
                    ]);
                }
                return $this->decision('suspicious_request:' . $suspiciousHit, [
                    'category' => 'intrusion',
                    'severity' => 'medium',
                    'reason' => 'suspicious_request',
                    'ruleId' => $suspiciousHit,
                    'modeKey' => 'suspicious_request',
                    'statusCode' => 403,
                    'targetLabel' => $this->target($method, $path, 'Suspicious:' . $suspiciousHit),
                    'detail' => 'Suspicious request detected.',
                ]);
            }
        }

        return null;
    }

    private function isFloodExempt(string $rawPath): bool
    {
        return isset($this->floodExemptNormalized[self::normalizePath($rawPath)]);
    }

    private function target(string $method, string $path, string $summary): string
    {
        return SlarkCompat::composeTargetLabel($this->siteLabel, $method . ' ' . $path . ' · ' . $summary);
    }

    /**
     * @param array{
     *   category: string,
     *   severity: string,
     *   reason: string,
     *   ruleId: string,
     *   modeKey: string,
     *   statusCode: int,
     *   detail: string,
     *   targetLabel: string,
     *   retryAfterSec?: int|null
     * } $opts
     */
    private function decision(string $name, array $opts): Detection
    {
        $blocked = $this->settings->blocksDetection($opts['modeKey']);
        return new Detection(
            name: $name,
            category: $opts['category'],
            severity: $opts['severity'],
            blocked: $blocked,
            action: $blocked ? 'blocked' : 'observed',
            statusCode: $blocked ? $opts['statusCode'] : 200,
            detail: $opts['detail'],
            ruleId: $opts['ruleId'],
            reason: $opts['reason'],
            targetLabel: $opts['targetLabel'],
            retryAfterSec: $blocked ? ($opts['retryAfterSec'] ?? null) : null,
        );
    }
}
