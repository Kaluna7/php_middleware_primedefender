<?php

declare(strict_types=1);

namespace PrimeDefender;

/** Sliding-window counter aligned with Slark `recordRateWindow` (count only allowed hits). */
final class RateLimit
{
    /** @var array<string, float[]> */
    private array $events = [];

    private function prune(array &$bucket, float $cutoff): void
    {
        while ($bucket !== [] && $bucket[0] < $cutoff) {
            array_shift($bucket);
        }
    }

    /** Legacy counter (always records). Use `recordWindow` for rate limits. */
    public function hit(string $key, int $windowSeconds): int
    {
        [$allowed, $hits] = $this->recordWindow($key, $windowSeconds, 2 ** 31 - 1);
        return $allowed ? $hits : max($hits, 1);
    }

    /**
     * @return array{0: bool, 1: int, 2: int}
     */
    public function recordWindow(string $key, int $windowSeconds, int $maxPerWindow): array
    {
        $now = microtime(true);
        if (!isset($this->events[$key])) {
            $this->events[$key] = [];
        }
        $bucket = &$this->events[$key];
        $cutoff = $now - $windowSeconds;
        $this->prune($bucket, $cutoff);
        $allowed = count($bucket) < $maxPerWindow;
        if ($allowed) {
            $bucket[] = $now;
        }
        $hits = count($bucket);
        $retryAfter = $hits > 0 ? max(1, (int) ceil($bucket[0] + $windowSeconds - $now)) : 1;
        return [$allowed, $hits, $retryAfter];
    }

    public function countRecent(string $key, int $windowSeconds): int
    {
        $now = microtime(true);
        $bucket = $this->events[$key] ?? null;
        if ($bucket === null) {
            return 0;
        }
        $this->prune($bucket, $now - $windowSeconds);
        return count($bucket);
    }
}
