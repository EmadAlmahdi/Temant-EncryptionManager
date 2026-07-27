<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

demoRespond([
    'phpVersion' => PHP_VERSION,
    'opensslLoaded' => extension_loaded('openssl'),
    'keyFingerprint' => strtoupper(substr(hash('sha256', $_SESSION['demo_secret']), 0, 8)),
]);
