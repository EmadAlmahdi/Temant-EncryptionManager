<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    demoRespond(['ok' => false, 'error' => 'Method not allowed.'], 405);
}

$body = demoRequestBody();
$retireCurrent = ($body['retireCurrent'] ?? true) !== false;

$oldSecret = $_SESSION['demo_secret'];
$newSecret = bin2hex(random_bytes(32));

// Exercise the real method on a real manager instance (not just our own session bookkeeping
// below), so this demo is actually driving EncryptionManager::updateSecret(), not a
// reimplementation of what it does.
$manager->updateSecret($newSecret, $retireCurrent);

// PHP tears down $manager at the end of this request either way, so the session is what
// carries the rotation forward to the next request — mirroring what updateSecret() just did.
if ($retireCurrent) {
    array_unshift($_SESSION['demo_retired_secrets'], $oldSecret);
}
$_SESSION['demo_secret'] = $newSecret;

demoRespond([
    'ok' => true,
    'retiredCurrent' => $retireCurrent,
    'oldKeyFingerprint' => demoFingerprint($oldSecret),
    'newKeyFingerprint' => demoFingerprint($newSecret),
    'retiredCount' => count($_SESSION['demo_retired_secrets']),
]);
