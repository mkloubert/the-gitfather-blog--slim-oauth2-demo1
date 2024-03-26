<?php

// MIT License
//
// Copyright (c) 2024 Marcel Joachim Kloubert (https://marcel.coffee)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// we should use strict data types
declare(strict_types=1);

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;
use Slim\Factory\AppFactory;
use Slim\Factory\ServerRequestCreatorFactory;

// composer autoloader
require __DIR__ . '/../vendor/autoload.php';

// JWT settings
define("TGF_JWT_ALGO", 'HS256');
define("TGF_JWT_LIFETIME", 3600);

// should be come from database later
$clientId = trim(strval(getenv("TGF_CLIENT_ID")));
$clientSecret = trim(strval(getenv("TGF_CLIENT_SECRET")));

// basic JWT settings from environment variables
$jwtKey = strval(getenv("TGF_JWT_SECRET"));
$jwtBasePayload = json_decode(
    strval(getenv("TGF_BASE_PAYLOAD")), true
);

$app = AppFactory::create();

// parse JSON, XML, forms, etc. automatically
$app->addBodyParsingMiddleware();

// middleware
$checkJWT = function(Request $request, RequestHandler $handler) use ($app, $clientId, $clientSecret, $jwtKey) {
    $response = $app->getResponseFactory()->createResponse();

    $autherization = trim(@$request->getHeader('Authorization')[0]);
    if (stripos($autherization, 'bearer ') === 0) {
        // starts with 'bearer '
        $jwt = trim(substr($autherization, 7));

        try {
            $decodedJWT = JWT::decode($jwt, new Key($jwtKey, TGF_JWT_ALGO));

            $request = $request->withAttribute("CURRENT_JWT", $decodedJWT);

            return $handler->handle($request);
        } catch (Exception $ex) {
            // parsing failed
        }
    }

    // we have no valid JWT
    $response->withStatus(400)
        ->withHeader('Content-Type', 'application/json');

    $response->getBody()->write(json_encode([
        'error' => 'invalid_grant'
    ]));

    return $response;
};

// endpoint to create a token
$app->post('/oauth2/token', function (Request $request, Response $response) use ($clientId, $clientSecret, $jwtBasePayload, $jwtKey) {
    $body = $request->getParsedBody();

    if (is_array($body)) {
        $response = $response->withStatus(200)
            ->withHeader('Content-Type', 'text/plain');

        if (@$body['grant_type'] === "client_credentials") {
            if (
                @$body['client_id'] === $clientId &&
                @$body['client_secret'] === $clientSecret
            ) {
                // valid, generate token ...

                $now = time();

                $jwtPayload = array_merge($jwtBasePayload, [  
                    'iat' => $now,
                    'nbf' => $now,
                    'exp' => $now + TGF_JWT_LIFETIME,
                    'client_id' => $body['client_id']
                ]);

                $encodedJWT = JWT::encode($jwtPayload, $jwtKey, TGF_JWT_ALGO);

                $response = $response->withStatus(200)
                    ->withHeader('Content-Type', 'application/json');

                $response->getBody()->write(json_encode([
                    'access_token' => $encodedJWT,
                    "expires_in" => TGF_JWT_LIFETIME,
                ]));
            } else {
                // invalid credentials

                $response = $response->withStatus(401)
                    ->withHeader('Content-Type', 'application/json');

                $response->getBody()->write(json_encode([
                    'error' => 'invalid_client'
                ]));
            }
        } else {
            // grant_type not supported

            $response = $response->withStatus(400)
                ->withHeader('Content-Type', 'application/json');

            $response->getBody()->write(json_encode([
                'error' => 'unsupported_grant_type'
            ]));
        }
    } else {
        // invalid input data

        $response = $response->withStatus(400)
            ->withHeader('Content-Type', 'application/json');

        $response->getBody()->write(json_encode([
            'error' => 'invalid_request'
        ]));
    }

	return $response;
});

// a test endpoint, which demonstrates how to
// validate JWT with middleware in `$checkJWT`
// closure function
$app->get('/user', function (Request $request, Response $response) {
    $jwt = $request->getAttribute("CURRENT_JWT");

	$response = $response->withStatus(200)
            ->withHeader('Content-Type', 'application/json');

    $response->getBody()->write(json_encode($jwt));

	return $response;
})->add($checkJWT);

$response = $app->run();
