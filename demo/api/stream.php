<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

use Temant\EncryptionManager\EncryptionException;

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    demoRespond(['ok' => false, 'error' => 'Method not allowed.'], 405);
}

demoRequireUpload('file');

$chunkSize = isset($_POST['chunkSize']) ? max(1, (int) $_POST['chunkSize']) : 65536;
$password = isset($_POST['password']) && $_POST['password'] !== '' ? (string) $_POST['password'] : null;

$tmpDir = sys_get_temp_dir() . '/temant_demo_' . bin2hex(random_bytes(6));
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
    $originalHash = hash_file('sha256', $inPath);

    $start = microtime(true);
    $manager->encryptStreamedFile($inPath, $encPath, $password, $chunkSize);
    $encryptMs = (microtime(true) - $start) * 1000;

    $encryptedBytes = filesize($encPath);
    $chunkCount = (int) max(1, ceil(max(1, $originalBytes) / $chunkSize));

    $start = microtime(true);
    $manager->decryptStreamedFile($encPath, $outPath, $password);
    $decryptMs = (microtime(true) - $start) * 1000;

    $integrityMatch = hash_file('sha256', $outPath) === $originalHash;

    // Flip one byte of ciphertext and confirm decryption now fails — proving the chunk/nonce
    // binding described in StreamCipher actually rejects tampering, not just claims to.
    copy($encPath, $tamperPath);
    $bytes = (string) file_get_contents($tamperPath);
    $lastIndex = strlen($bytes) - 1;
    $bytes[$lastIndex] = chr(ord($bytes[$lastIndex]) ^ 1);
    file_put_contents($tamperPath, $bytes);

    $tamperDetected = false;
    try {
        $manager->decryptStreamedFile($tamperPath, $tamperOutPath, $password);
    } catch (EncryptionException) {
        $tamperDetected = true;
    }

    demoRespond([
        'ok' => true,
        'originalBytes' => $originalBytes,
        'encryptedBytes' => $encryptedBytes,
        'chunkSize' => $chunkSize,
        'chunkCount' => $chunkCount,
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
