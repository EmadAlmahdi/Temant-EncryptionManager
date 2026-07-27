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

// Retired secrets from previous rotations (see rotate.php). Rebuilding the keyring from
// per-request state like this — rather than keeping one long-lived PHP object — is exactly the
// pattern EncryptionManager's $retiredSecrets constructor argument is designed for, since a
// typical PHP-FPM app is stateless across requests too.
if (!isset($_SESSION['demo_retired_secrets'])) {
    $_SESSION['demo_retired_secrets'] = [];
}

$manager = new EncryptionManager(
    $_SESSION['demo_secret'],
    EncryptionConfig::defaults(),
    $_SESSION['demo_retired_secrets']
);

/**
 * A short, non-reversible label for a secret, safe to display in the UI.
 */
function demoFingerprint(string $secret): string
{
    return strtoupper(substr(hash('sha256', $secret), 0, 8));
}

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

/**
 * Validate a $_FILES upload, responding with a clear error (rather than a generic "no file")
 * when it was rejected by PHP's own upload_max_filesize/post_max_size before this script ran.
 */
function demoRequireUpload(string $field): void
{
    if (!isset($_FILES[$field])) {
        demoRespond(['ok' => false, 'error' => 'No file uploaded.'], 400);
    }

    $error = $_FILES[$field]['error'];

    if ($error === UPLOAD_ERR_INI_SIZE || $error === UPLOAD_ERR_FORM_SIZE) {
        demoRespond(['ok' => false, 'error' => 'File exceeds the server\'s upload size limit.'], 400);
    }

    if ($error !== UPLOAD_ERR_OK) {
        demoRespond(['ok' => false, 'error' => 'File upload failed.'], 400);
    }
}
