<?php

declare(strict_types=1);

namespace PrimeDefender;

final class Detection
{
    public function __construct(
        public readonly string $name,
        public readonly string $category,
        public readonly string $severity,
        public readonly bool $blocked,
        public readonly string $action,
        public readonly int $statusCode,
        public readonly string $detail,
        public readonly ?string $ruleId = null,
        public readonly ?string $reason = null,
        public readonly ?string $targetLabel = null,
        public readonly ?int $retryAfterSec = null,
    ) {
    }
}
