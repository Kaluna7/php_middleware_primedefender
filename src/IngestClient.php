<?php

declare(strict_types=1);

namespace PrimeDefender;

final class IngestClient
{
    public static function resolveIngestUrl(string $bridgeBaseUrl): string
    {
        $u = rtrim(trim($bridgeBaseUrl), '/');
        $parsed = parse_url($u);
        if ($parsed !== false && isset($parsed['scheme'])) {
            $path = $parsed['path'] ?? '';
            if ($path === '' || $path === '/') {
                return $u . '/ingest';
            }
            return $u;
        }
        return str_ends_with($u, '/ingest') ? $u : $u . '/ingest';
    }

    /**
     * @param array<string, mixed> $payload
     * @return array{ok: bool, status: int, bodyText: string}
     */
    public static function postIncident(
        string $ingestUrl,
        string $apiKey,
        array $payload,
        float $timeoutSeconds = 3.0,
    ): array {
        $json = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        $headers = [
            'Content-Type: application/json',
            'X-Api-Key: ' . $apiKey,
            'Authorization: Bearer ' . $apiKey,
        ];

        if (function_exists('curl_init')) {
            return self::postWithCurl($ingestUrl, $headers, $json, $timeoutSeconds);
        }

        return self::postWithStream($ingestUrl, $headers, $json, $timeoutSeconds);
    }

    /**
     * @param list<string> $headers
     * @return array{ok: bool, status: int, bodyText: string}
     */
    private static function postWithCurl(
        string $url,
        array $headers,
        string $body,
        float $timeoutSeconds,
    ): array {
        $ch = curl_init($url);
        if ($ch === false) {
            return ['ok' => false, 'status' => 0, 'bodyText' => 'curl_init failed'];
        }

        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => max(1, (int) ceil($timeoutSeconds)),
            CURLOPT_CONNECTTIMEOUT => max(1, (int) ceil($timeoutSeconds)),
        ]);

        $bodyText = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($bodyText === false) {
            return ['ok' => false, 'status' => $status, 'bodyText' => ''];
        }

        return ['ok' => $status >= 200 && $status < 300, 'status' => $status, 'bodyText' => $bodyText];
    }

    /**
     * @param list<string> $headers
     * @return array{ok: bool, status: int, bodyText: string}
     */
    private static function postWithStream(
        string $url,
        array $headers,
        string $body,
        float $timeoutSeconds,
    ): array {
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => implode("\r\n", $headers),
                'content' => $body,
                'timeout' => max(1, (int) ceil($timeoutSeconds)),
                'ignore_errors' => true,
            ],
        ]);

        $bodyText = @file_get_contents($url, false, $context);
        $status = 0;
        if (isset($http_response_header[0]) && preg_match('/\d{3}/', $http_response_header[0], $m)) {
            $status = (int) $m[0];
        }

        return [
            'ok' => $status >= 200 && $status < 300,
            'status' => $status,
            'bodyText' => $bodyText !== false ? $bodyText : '',
        ];
    }
}
