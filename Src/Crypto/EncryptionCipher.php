<?php

declare(strict_types=1);

namespace Temant\EncryptionManager\Crypto;

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
     * Both variants use the standard 96-bit (12-byte) GCM IV; this is fixed by construction
     * (rather than queried from OpenSSL at runtime) since AEAD security depends on it never
     * silently changing.
     *
     * @return int<12, 12>
     */
    public function ivLength(): int
    {
        return 12;
    }

    /**
     * Get the key length (bytes) required by this cipher.
     *
     * @return 16|32 32 for AES-256-GCM, 16 for AES-128-GCM.
     */
    public function keyLength(): int
    {
        return match ($this) {
            self::AES_256_GCM => 32,
            self::AES_128_GCM => 16,
        };
    }
}