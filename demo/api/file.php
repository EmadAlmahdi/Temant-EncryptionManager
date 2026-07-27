<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

use Temant\EncryptionManager\EncryptionException;

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    demoRespond(['ok' => false, 'error' => 'Method not allowed.'], 405);
}

demoRequireUpload('file');

// encryptFile() loads the whole file into memory, unlike encryptStreamedFile() — keep this
// demo's cap well below the streamed endpoint's to make that difference concrete.
const MAX_UPLOAD_BYTES = 2 * 1024 * 1024;

$password = isset($_POST['password']) && $_POST['password'] !== '' ? (string) $_POST['password'] : null;

$tmpDir = sys_get_temp_dir() . '/temant_demo_file_' . bin2hex(random_bytes(6));
mkdir($tmpDir);

$inPath = $tmpDir . '/in';
$encPath = $tmpDir . '/enc';
$outPath = $tmpDir . '/out';
$tamperPath = $tmpDir . '/tamper';
$tamperOutPath = $tmpDir . '/tamper-out';

try {
    if (!move_uploaded_file($_FILES['file']['tmp_name'], $inPath)) {
        demoRespond(['ok' => false, 'error' => 'Failed to receive uploaded file.'], 400);
    }

    $originalBytes = filesize($inPath);

    if ($originalBytes > MAX_UPLOAD_BYTES) {
        demoRespond([
            'ok' => false,
            'error' => sprintf(
                'File is %.1f MB — encryptFile() loads it fully into memory, so this demo caps it at 2 MB. Use streamed file encryption for larger files.',
                $originalBytes / (1024 * 1024)
            ),
        ], 400);
    }

    $originalHash = hash_file('sha256', $inPath);

    $start = microtime(true);
    $manager->encryptFile($inPath, $encPath, $password);
    $encryptMs = (microtime(true) - $start) * 1000;

    $payload = (string) file_get_contents($encPath);

    $start = microtime(true);
    $manager->decryptFile($encPath, $outPath, $password);
    $decryptMs = (microtime(true) - $start) * 1000;

    $integrityMatch = hash_file('sha256', $outPath) === $originalHash;

    // Flip one character of the payload and confirm decryption now fails — the same AEAD
    // tag that protects encryptString() payloads protects these too.
    $tamperedPayload = $payload;
    $lastIndex = strlen($tamperedPayload) - 1;
    $tamperedPayload[$lastIndex] = $tamperedPayload[$lastIndex] === 'A' ? 'B' : 'A';
    file_put_contents($tamperPath, $tamperedPayload);

    $tamperDetected = false;
    try {
        $manager->decryptFile($tamperPath, $tamperOutPath, $password);
    } catch (EncryptionException) {
        $tamperDetected = true;
    }

    demoRespond([
        'ok' => true,
        'originalBytes' => $originalBytes,
        'payloadBytes' => strlen($payload),
        'payload' => $payload,
        'integrityMatch' => $integrityMatch,
        'tamperDetected' => $tamperDetected,
        'encryptMs' => round($encryptMs, 2),
        'decryptMs' => round($decryptMs, 2),
    ]);
} catch (EncryptionException $e) {
    demoRespond(['ok' => false, 'error' => $e->getMessage()], 400);
} finally {
    foreach ([$inPath, $encPath, $outPath, $tamperPath, $tamperOutPath] as $file) {
        if (is_file($file)) {
            unlink($file);
        }
    }
    if (is_dir($tmpDir)) {
        rmdir($tmpDir);
    }
}
