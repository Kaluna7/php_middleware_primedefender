<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use PrimeDefender\PrimeDefender;

// Set PRIMEDEFENDER_* env vars (or load a .env file before this script runs).
PrimeDefender::guard();

echo 'hello';
