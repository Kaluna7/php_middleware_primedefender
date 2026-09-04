<?php

declare(strict_types=1);

/**
 * Slim 4 + PrimeDefender (PSR-15 middleware).
 *
 * composer require slim/slim nyholm/psr7 primedefender/php
 *
 * Set PRIMEDEFENDER_* env vars before running.
 */

use PrimeDefender\PrimeDefender;
use PrimeDefender\PrimeDefenderSettings;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Factory\AppFactory;

$app = AppFactory::create();

$settings = PrimeDefenderSettings::fromEnv();
$responseFactory = $app->getResponseFactory();

// Add after routing middleware so path is available; before route handlers.
$app->add(PrimeDefender::middleware($settings, $responseFactory));

$app->get('/', function (Request $request, Response $response): Response {
    $response->getBody()->write('ok');
    return $response;
});

$app->run();
