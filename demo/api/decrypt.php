<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

use Temant\EncryptionManager\EncryptionException;

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    demoRespond(['ok' => false, 'error' => 'Method not allowed.'], 405);
}

$body = demoRequestBody();
$payload = is_string($body['payload'] ?? null) ? $body['payload'] : '';
$password = is_string($body['password'] ?? null) ? $body['password'] : '';

if ($payload === '') {
    demoRespond(['ok' => false, 'error' => 'Payload must not be empty.'], 400);
}

try {
    $plaintext = $manager->decryptString($payload, $password !== '' ? $password : null);
    demoRespond(['ok' => true, 'result' => $plaintext]);
} catch (EncryptionException $e) {
    demoRespond(['ok' => false, 'error' => $e->getMessage()], 400);
}
