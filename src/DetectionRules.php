<?php

declare(strict_types=1);

namespace PrimeDefender;

final class DetectionRules
{
    private const SCANNER_UA_IDS = [
        'sqlmap', 'nikto', 'nmap', 'masscan', 'zgrab', 'wpscan', 'acunetix', 'nessus', 'openvas',
        'qualys', 'burp', 'burpsuite', 'owasp_zap', 'zaproxy', 'arachni', 'skipfish', 'w3af',
        'dirbuster', 'dirb', 'gobuster', 'ffuf', 'feroxbuster', 'wfuzz', 'hydra', 'medusa',
        'metasploit', 'msf', 'nuclei', 'httpx', 'subfinder', 'amass', 'shodan', 'censys', 'whatweb',
        'jaeles', 'dalfox', 'xsstrike', 'commix', 'tplmap', 'fimap', 'uniscan', 'paros', 'webscarab',
        'vega', 'grabber', 'havij', 'pangolin', 'absinthe', 'sqlninja', 'bbscan', 'xray', 'gau',
        'gauri', 'waybackurls', 'hakrawler', 'meg', 'netsparker', 'appscan', 'webinspect',
        'securityscan', 'exploit', 'vulnerability', 'zmap', 'nmap_scripting_engine',
    ];

    private const AUTOMATION_UA_IDS = [
        'headlesschrome', 'headless', 'phantomjs', 'playwright', 'puppeteer', 'selenium',
        'webdriver', 'scrapy', 'mechanize', 'httpclient',
    ];

    private const BOT_CLIENT_UA_IDS = [
        'curl', 'wget', 'python_requests', 'python_urllib', 'aiohttp', 'libwww_perl', 'lwp_trivial',
        'go_http_client', 'java_', 'apache_httpclient', 'okhttp', 'axios', 'node_fetch', 'undici',
        'postmanruntime', 'insomnia', 'httpie', 'rest_client', 'winhttp', 'powershell',
    ];

    private const CRAWLER_UA_IDS = [
        'googlebot', 'bingbot', 'baiduspider', 'yandexbot', 'petalbot', 'semrushbot', 'ahrefsbot',
        'mj12bot', 'dotbot', 'bytespider', 'gptbot', 'claudebot', 'ccbot', 'spider', 'crawler', 'scan',
    ];

    /** @var array<string, mixed>|null */
    private static ?array $exported = null;

    /** @var list<Rule>|null */
    private static ?array $sqliRules = null;
    /** @var list<Rule>|null */
    private static ?array $xssRules = null;
    /** @var list<Rule>|null */
    private static ?array $pathTraversalRules = null;
    /** @var list<Rule>|null */
    private static ?array $fileInclusionRules = null;
    /** @var list<Rule>|null */
    private static ?array $cmdInjectionRules = null;
    /** @var list<Rule>|null */
    private static ?array $authBypassRules = null;
    /** @var list<Rule>|null */
    private static ?array $suspiciousRequestRules = null;
    /** @var list<Rule>|null */
    private static ?array $scannerPathRules = null;
    /** @var list<Rule>|null */
    private static ?array $defaultUaBlock = null;

    /** @return list<Rule> */
    public static function getSqliRules(): array
    {
        self::ensureLoaded();
        return self::$sqliRules ?? [];
    }

    /** @return list<Rule> */
    public static function getXssRules(): array
    {
        self::ensureLoaded();
        return self::$xssRules ?? [];
    }

    /** @return list<Rule> */
    public static function getPathTraversalRules(): array
    {
        self::ensureLoaded();
        return self::$pathTraversalRules ?? [];
    }

    /** @return list<Rule> */
    public static function getFileInclusionRules(): array
    {
        self::ensureLoaded();
        return self::$fileInclusionRules ?? [];
    }

    /** @return list<Rule> */
    public static function getCmdInjectionRules(): array
    {
        self::ensureLoaded();
        return self::$cmdInjectionRules ?? [];
    }

    /** @return list<Rule> */
    public static function getAuthBypassRules(): array
    {
        self::ensureLoaded();
        return self::$authBypassRules ?? [];
    }

    /** @return list<Rule> */
    public static function getSuspiciousRequestRules(): array
    {
        self::ensureLoaded();
        return self::$suspiciousRequestRules ?? [];
    }

    /** @return list<Rule> */
    public static function getScannerPathRules(): array
    {
        self::ensureLoaded();
        return self::$scannerPathRules ?? [];
    }

    /** @return list<Rule> */
    public static function getDefaultUaBlock(): array
    {
        self::ensureLoaded();
        return self::$defaultUaBlock ?? [];
    }

    /** @return list<string> */
    public static function getLoginPaths(): array
    {
        self::ensureLoaded();
        return self::$exported['LOGIN_PATHS'] ?? [];
    }

    /** @return list<string> */
    public static function getSensitiveScanPaths(): array
    {
        self::ensureLoaded();
        return self::$exported['SENSITIVE_SCAN_PATHS'] ?? [];
    }

    public static function classifyUaHit(?string $ruleId): ?string
    {
        if ($ruleId === null || $ruleId === '') {
            return null;
        }
        if (
            in_array($ruleId, self::SCANNER_UA_IDS, true)
            || preg_match('/\b(scan|exploit|vuln|security)\b/i', $ruleId) === 1
        ) {
            return 'scanner';
        }
        if (in_array($ruleId, self::AUTOMATION_UA_IDS, true)) {
            return 'automation';
        }
        if (in_array($ruleId, self::BOT_CLIENT_UA_IDS, true)) {
            return 'bot_client';
        }
        if (
            in_array($ruleId, self::CRAWLER_UA_IDS, true)
            || preg_match('/\b(bot|spider|crawler)\b/i', $ruleId) === 1
        ) {
            return 'crawler';
        }
        return 'suspicious';
    }

    /**
     * @param array{ua: string, method: string, headerBlob: string, pathQuery: string} $ctx
     */
    public static function detectBotActivity(array $ctx): ?string
    {
        $checks = [
            [static fn (array $c) => trim($c['ua']) === '', 'empty_ua'],
            [static fn (array $c) => trim($c['ua']) !== '' && strlen(trim($c['ua'])) < 12, 'short_ua'],
            [
                static fn (array $c) => preg_match('/^[a-z0-9._-]+$/i', $c['ua']) === 1
                    && strlen($c['ua']) < 24,
                'minimal_ua_token',
            ],
            [static fn (array $c) => preg_match('/\b(bot|crawler|spider|scraper|scan|probe)\b/i', $c['ua']) === 1, 'ua_bot_keyword'],
            [static fn (array $c) => $c['method'] === 'GET' && !str_contains($c['headerBlob'], 'accept'), 'missing_accept'],
            [
                static fn (array $c) => $c['method'] === 'GET'
                    && !str_contains($c['headerBlob'], 'accept-language'),
                'missing_accept_language',
            ],
            [static fn (array $c) => $c['ua'] === 'Mozilla/5.0', 'fake_mozilla_minimal'],
        ];

        foreach ($checks as [$test, $id]) {
            if ($test($ctx)) {
                return $id;
            }
        }
        return null;
    }

    private static function ensureLoaded(): void
    {
        if (self::$exported !== null) {
            return;
        }

        $jsonPath = __DIR__ . '/rules_export.json';
        $raw = file_get_contents($jsonPath);
        if ($raw === false) {
            throw new \RuntimeException('Failed to load rules_export.json');
        }
        $exported = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        self::$exported = $exported;

        self::$sqliRules = self::compileBucket($exported['SQLI_RULES'] ?? []);
        self::$xssRules = self::compileBucket($exported['XSS_RULES'] ?? []);
        self::$pathTraversalRules = self::compileBucket($exported['PATH_TRAVERSAL_RULES'] ?? []);
        self::$fileInclusionRules = self::compileBucket($exported['FILE_INCLUSION_RULES'] ?? []);
        self::$cmdInjectionRules = self::compileBucket($exported['CMD_INJECTION_RULES'] ?? []);
        self::$authBypassRules = self::compileBucket($exported['AUTH_BYPASS_RULES'] ?? []);
        self::$suspiciousRequestRules = self::compileBucket($exported['SUSPICIOUS_REQUEST_RULES'] ?? []);
        self::$scannerPathRules = self::compileBucket($exported['SCANNER_PATH_RULES'] ?? []);
        self::$defaultUaBlock = self::compileBucket($exported['DEFAULT_UA_BLOCK'] ?? []);
    }

    /**
     * @param list<array{id: string, source: string, flags?: string}> $raw
     * @return list<Rule>
     */
    private static function compileBucket(array $raw): array
    {
        $rules = [];
        foreach ($raw as $item) {
            $rules[] = new Rule(
                $item['id'],
                self::compilePattern($item['source'], $item['flags'] ?? 'i'),
            );
        }
        return self::dedupeRules($rules);
    }

    /**
     * @param list<Rule> $rules
     * @return list<Rule>
     */
    private static function dedupeRules(array $rules): array
    {
        $seen = [];
        $out = [];
        foreach ($rules as $rule) {
            if (isset($seen[$rule->id])) {
                continue;
            }
            $seen[$rule->id] = true;
            $out[] = $rule;
        }
        return $out;
    }

    /**
     * Match primedefender-fastapi `_js_regex_to_python`: a JS `.source` of `\x[` is not a
     * hex escape, so treat `\x` as a literal backslash-x (otherwise `x64` in Chrome UAs matches).
     */
    public static function fixJsRegexSource(string $source): string
    {
        $hex = '0123456789abcdefABCDEF';
        $out = '';
        $len = strlen($source);
        $i = 0;
        while ($i < $len) {
            if ($source[$i] === '\\' && ($i + 1) < $len && $source[$i + 1] === 'x') {
                $a = $source[$i + 2] ?? '';
                $b = $source[$i + 3] ?? '';
                $c = $source[$i + 4] ?? '';
                if (
                    $a !== ''
                    && $b !== ''
                    && str_contains($hex, $a)
                    && str_contains($hex, $b)
                    && ($c === '' || !str_contains($hex, $c))
                ) {
                    $out .= substr($source, $i, 4);
                    $i += 4;
                    continue;
                }
                $out .= '\\\\x';
                $i += 2;
                continue;
            }
            $out .= $source[$i];
            $i++;
        }
        return $out;
    }

    public static function compilePattern(string $source, string $flags = 'i'): string
    {
        $fixed = self::fixJsRegexSource($source);
        $modifiers = self::jsFlagsToPcre($flags);
        return '#' . str_replace('#', '\#', $fixed) . '#' . $modifiers;
    }

    public static function jsFlagsToPcre(string $flags): string
    {
        $mods = '';
        if (str_contains($flags, 'i')) {
            $mods .= 'i';
        }
        if (str_contains($flags, 's')) {
            $mods .= 's';
        }
        if (str_contains($flags, 'm')) {
            $mods .= 'm';
        }
        return $mods;
    }
}
