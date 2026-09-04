<?php

declare(strict_types=1);

namespace PrimeDefender;

final class SlarkCompat
{
    private const STATIC_ASSET_RE = '/\.(?:avif|bmp|css|gif|ico|jpeg|jpg|js|json|map|mp3|mp4|png|svg|txt|webm|webp|woff2?)$/i';

    public static function composeTargetLabel(string $siteLabel, ?string $summary = null): string
    {
        if ($summary !== null && trim($summary) !== '') {
            return $siteLabel . ' · ' . trim($summary);
        }
        return $siteLabel;
    }

    public static function buildSiteLabel(string $siteId, string $siteRegionLabel): string
    {
        $parts = [];
        if (trim($siteId) !== '') {
            $parts[] = trim($siteId);
        }
        if (trim($siteRegionLabel) !== '') {
            $parts[] = trim($siteRegionLabel);
        }
        return $parts !== [] ? implode(' · ', $parts) : 'Protected site';
    }

    public static function shouldSkipInspection(string $method, string $path): bool
    {
        $m = strtoupper($method !== '' ? $method : 'GET');
        $p = explode('?', $path !== '' ? $path : '/', 2)[0];
        return ($m === 'GET' || $m === 'HEAD')
            && ($p === '/health' || $p === '/favicon.ico' || preg_match(self::STATIC_ASSET_RE, $p) === 1);
    }
}
