# Temant Encryption Manager

![Build Status](https://github.com/EmadAlmahdi/Temant-EncryptionManager/actions/workflows/ci.yml/badge.svg)
![Coverage Status](https://codecov.io/gh/EmadAlmahdi/Temant-EncryptionManager/branch/main/graph/badge.svg)
![License](https://img.shields.io/github/license/EmadAlmahdi/Temant-EncryptionManager)
![PHPStan](https://img.shields.io/badge/PHPStan-level%20max-brightgreen)

Temant Encryption Manager is a small, focused authenticated-encryption (AEAD) library for PHP,
built exclusively on AES-GCM. It provides a simple API for encrypting and decrypting strings and
files, with two independent key-derivation modes and support for key rotation and large-file
streaming.

- **AES-256-GCM or AES-128-GCM only** — no legacy unauthenticated modes (CBC/ECB) to misuse.
- **Two key-derivation modes**: HKDF-SHA256 for high-entropy app secrets, PBKDF2-SHA256 (with a
  per-message random salt) for human passwords.
- **Versioned, self-describing payloads** — encrypted strings are safe to store as text.
- **Key rotation** — decrypt data encrypted under a previous app secret via a retired-key keyring.
- **Streaming file encryption** — encrypt/decrypt large files in fixed-size chunks with constant
  memory usage.

## Installation

```bash
composer require temant/encryption-manager
```

Requires PHP `^8.5` and the `openssl` extension.

## Usage

### Encrypting strings (app secret)

```php
use Temant\EncryptionManager\EncryptionManager;

// The secret should be a high-entropy value (e.g. a 32+ byte random string from your
// app's secrets manager), not a human password.
$encryption = new EncryptionManager('your-high-entropy-app-secret');

$encrypted = $encryption->encryptString('Hello, World!');
$decrypted = $encryption->decryptString($encrypted);

echo "Encrypted: $encrypted\n";
echo "Decrypted: $decrypted\n";
```

`encryptString()` returns a versioned, printable payload (`v1:` + base64) safe to store in a
database column or JSON field.

### Encrypting strings with a password

Pass a password as the second argument to switch to PBKDF2-based key derivation with a random
per-message salt, instead of the app-secret-derived key:

```php
$plainText = 'Sensitive Data';
$password = 'your-secure-password';

$encrypted = $encryption->encryptString($plainText, $password);
$decrypted = $encryption->decryptString($encrypted, $password);
```

### Custom configuration

Cipher choice, PBKDF2 iteration count, salt/tag sizes, and the HKDF info string are all
configurable via `EncryptionConfig`:

```php
use Temant\EncryptionManager\Crypto\EncryptionCipher;
use Temant\EncryptionManager\Crypto\EncryptionConfig;

$config = new EncryptionConfig(
    cipher: EncryptionCipher::AES_128_GCM, // or AES_256_GCM (default)
    pbkdf2Iterations: 250_000,             // default: 150_000
    saltBytes: 16,                         // default: 16
    tagBytes: 16,                          // default: 16
    hkdfInfo: 'my-app-name',               // default: "temant-encryption"
);

$encryption = new EncryptionManager('your-app-secret', $config);
```

A manager only decrypts payloads produced with a matching cipher — mixing `AES_128_GCM` and
`AES_256_GCM` payloads under one manager instance throws. `pbkdf2Iterations`, `saltBytes`, and
`tagBytes` must all be positive integers; `EncryptionConfig` validates this at construction time
and throws `EncryptionException` immediately rather than failing cryptically later inside OpenSSL.

### Key rotation

Rotating your app secret doesn't have to invalidate previously-encrypted data. By default,
`updateSecret()` keeps the old secret in an in-memory keyring, so old payloads stay decryptable:

```php
$encryption = new EncryptionManager('current-secret');
$oldPayload = $encryption->encryptString('archived data');

// Later, e.g. during a scheduled secret rotation:
$encryption->updateSecret('new-secret'); // old-secret is retired, not discarded

$encryption->decryptString($oldPayload);       // still works (retired key)
$encryption->encryptString('new data');        // uses new-secret
```

To rotate without keeping the old secret around (immediately invalidating old data), pass
`retireCurrent: false`:

```php
$encryption->updateSecret('new-secret', retireCurrent: false);
```

If your process restarts and needs to rebuild the keyring (e.g. from a secrets manager), pass
retired secrets at construction time or add them later:

```php
$encryption = new EncryptionManager('current-secret', retiredSecrets: ['secret-from-2025-q4']);
// or:
$encryption->addRetiredSecret('secret-from-2025-q4');

// To permanently drop the keyring (old data becomes undecryptable):
$encryption->clearRetiredSecrets();
```

Key rotation only applies to app-secret mode. Password-mode encryption always derives its key
from the password you pass in, so there's nothing to rotate on the manager itself.

### File encryption

For small files, `encryptFile()`/`decryptFile()` load the whole file into memory and reuse the
same versioned payload format as `encryptString()`:

```php
$encryption->encryptFile('path/to/input/file.txt', 'path/to/encrypted/file.txt', 'file-password');
$encryption->decryptFile('path/to/encrypted/file.txt', 'path/to/decrypted/file.txt', 'file-password');
```

### Streaming file encryption (large files)

For large files, use `encryptStreamedFile()`/`decryptStreamedFile()` instead. They process the
file in fixed-size chunks (default 64 KB) instead of loading it fully into memory, and use a
distinct binary chunked format — not interchangeable with `encryptFile()`/`decryptFile()`:

```php
$encryption->encryptStreamedFile('path/to/large-input.bin', 'path/to/large-output.enc');
$encryption->decryptStreamedFile('path/to/large-output.enc', 'path/to/large-decrypted.bin');

// Optional password mode and a custom chunk size:
$encryption->encryptStreamedFile($input, $output, password: 'file-password', chunkSize: 1024 * 1024);
```

Each chunk is independently authenticated, and the chunk index plus a "final chunk" flag are
bound into that chunk's nonce. This means truncating, reordering, duplicating, or splicing chunks
is detected as an authentication failure during decryption rather than silently producing
corrupted output.

### Error handling

All failures — invalid payloads, tampered ciphertext, wrong passwords, cipher mismatches, missing
files, I/O errors — throw `Temant\EncryptionManager\EncryptionException`:

```php
use Temant\EncryptionManager\EncryptionException;

try {
    $encryption->decryptString($payload, $password);
} catch (EncryptionException $e) {
    // Never assume a caught exception means "wrong password" specifically —
    // the same exception type covers tampering, corruption, and config mismatches.
    log($e->getMessage());
}
```

## Running Tests

```bash
composer test      # PHPUnit
composer analyse    # PHPStan (level max)
composer check-all  # both
```

## License

This project is licensed under the [MIT License](LICENSE).
