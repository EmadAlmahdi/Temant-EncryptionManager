<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

use Temant\EncryptionManager\EncryptionException;

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    demoRespond(['ok' => false, 'error' => 'Method not allowed.'], 405);
}

$body = demoRequestBody();
$plaintext = is_string($body['plaintext'] ?? null) ? $body['plaintext'] : '';
$password = is_string($body['password'] ?? null) ? $body['password'] : '';

if ($plaintext === '') {
    demoRespond(['ok' => false, 'error' => 'Plaintext must not be empty.'], 400);
}

try {
    $payload = $manager->encryptString($plaintext, $password !== '' ? $password : null);
    demoRespond(['ok' => true, 'result' => $payload]);
} catch (EncryptionException $e) {
    demoRespond(['ok' => false, 'error' => $e->getMessage()], 400);
}
