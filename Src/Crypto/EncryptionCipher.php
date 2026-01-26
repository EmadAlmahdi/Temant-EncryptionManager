<?php

declare(strict_types=1);

namespace Temant\EncryptionManager\Crypto;

use Temant\EncryptionManager\EncryptionException;

/**
 * Supported AEAD ciphers.
 *
 * Only AES-GCM is supported to guarantee authenticated encryption.
 */
enum EncryptionCipher: string
{
    /**
     * AES-256-GCM (recommended default).
     */
    case AES_256_GCM = 'aes-256-gcm';

    /**
     * AES-128-GCM (faster, smaller key).
     */
    case AES_128_GCM = 'aes-128-gcm';

    /**
     * Get the IV length (bytes) required by this cipher.
     *
     * @throws EncryptionException If OpenSSL cannot determine IV length.
     */
    public function ivLength(): int
    {
        return openssl_cipher_iv_length($this->value);
    }

    /**
     * Get the key length (bytes) required by this cipher.
     *
     * @return int 32 for AES-256-GCM, 16 for AES-128-GCM.
     */
    public function keyLength(): int
    {
        return match ($this) {
            self::AES_256_GCM => 32,
            self::AES_128_GCM => 16,
        };
    }
}