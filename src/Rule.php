<?php

declare(strict_types=1);

namespace PrimeDefender;

final class Rule
{
    public function __construct(
        public readonly string $id,
        /** Compiled PCRE pattern including delimiters and modifiers. */
        public readonly string $pattern,
    ) {
    }
}
