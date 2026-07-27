<?php

declare(strict_types=1);

require __DIR__ . '/../../vendor/autoload.php';

use Temant\EncryptionManager\Crypto\EncryptionConfig;
use Temant\EncryptionManager\EncryptionManager;

header('Content-Type: application/json');

session_start();

if (!isset($_SESSION['demo_secret'])) {
    $_SESSION['demo_secret'] = bin2hex(random_bytes(32));
}

$manager = new EncryptionManager($_SESSION['demo_secret'], EncryptionConfig::defaults());

/**
 * Decode the JSON request body sent by the demo frontend.
 *
 * @return array<string, mixed>
 */
function demoRequestBody(): array
{
    $raw = file_get_contents('php://input');
    if ($raw === false || $raw === '') {
        return [];
    }

    $decoded = json_decode($raw, true);
    return is_array($decoded) ? $decoded : [];
}

/**
 * @param array<string, mixed> $payload
 */
function demoRespond(array $payload, int $status = 200): never
{
    http_response_code($status);
    echo json_encode($payload);
    exit;
}
