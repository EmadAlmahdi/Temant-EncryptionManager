<?php

declare(strict_types=1);

namespace Temant\EncryptionManager\Crypto;

use Temant\EncryptionManager\EncryptionException;

/**
 * Immutable configuration for encryption behavior.
 *
 * @psalm-immutable
 */
final class EncryptionConfig
{
    /**
     * @param EncryptionCipher $cipher Cipher to use.
     * @param int<1, max> $pbkdf2Iterations PBKDF2 iteration count for password mode.
     * @param int<1, max> $saltBytes Salt size for password mode (bytes).
     * @param int<1, max> $tagBytes Authentication tag size for GCM (bytes).
     * @param string $hkdfInfo HKDF "info" context string for app-secret key derivation.
     *
     * @throws EncryptionException If any numeric parameter is not a positive integer.
     */
    public function __construct(
        public readonly EncryptionCipher $cipher,
        public readonly int $pbkdf2Iterations,
        public readonly int $saltBytes,
        public readonly int $tagBytes,
        public readonly string $hkdfInfo,
    ) {
        if ($pbkdf2Iterations < 1) {
            throw EncryptionException::invalidConfig('pbkdf2Iterations must be at least 1.');
        }

        if ($saltBytes < 1) {
            throw EncryptionException::invalidConfig('saltBytes must be at least 1.');
        }

        if ($tagBytes < 1) {
            throw EncryptionException::invalidConfig('tagBytes must be at least 1.');
        }
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