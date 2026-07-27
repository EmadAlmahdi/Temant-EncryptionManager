<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

demoRespond([
    'phpVersion' => PHP_VERSION,
    'opensslLoaded' => extension_loaded('openssl'),
    'keyFingerprint' => demoFingerprint($_SESSION['demo_secret']),
    'retiredCount' => count($_SESSION['demo_retired_secrets']),
]);
