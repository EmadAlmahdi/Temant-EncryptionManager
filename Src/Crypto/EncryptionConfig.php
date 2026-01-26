<?php

declare(strict_types=1);

namespace Temant\EncryptionManager\Crypto;

/**
 * Immutable configuration for encryption behavior.
 *
 * @psalm-immutable
 */
final class EncryptionConfig
{
    /**
     * @param EncryptionCipher $cipher Cipher to use.
     * @param int $pbkdf2Iterations PBKDF2 iteration count for password mode.
     * @param int $saltBytes Salt size for password mode (bytes).
     * @param int $tagBytes Authentication tag size for GCM (bytes).
     * @param string $hkdfInfo HKDF "info" context string for app-secret key derivation.
     */
    public function __construct(
        public readonly EncryptionCipher $cipher,
        public readonly int $pbkdf2Iterations,
        public readonly int $saltBytes,
        public readonly int $tagBytes,
        public readonly string $hkdfInfo,
    ) {
    }

    /**
     * Create a safe default configuration.
     *
     * Defaults:
     * - cipher: AES-256-GCM
     * - PBKDF2 iterations: 150,000
     * - salt bytes: 16
     * - tag bytes: 16
     * - hkdf info: "temant-encryption"
     *
     * @return self
     */
    public static function defaults(): self
    {
        return new self(
            cipher: EncryptionCipher::AES_256_GCM,
            pbkdf2Iterations: 150_000,
            saltBytes: 16,
            tagBytes: 16,
            hkdfInfo: 'temant-encryption',
        );
    }
}