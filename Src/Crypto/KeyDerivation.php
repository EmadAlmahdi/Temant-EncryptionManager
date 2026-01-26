<?php

declare(strict_types=1);

namespace Temant\EncryptionManager\Crypto;

/**
 * Key derivation helpers.
 *
 * - App secret: HKDF-SHA256 (fast, deterministic; suitable for high-entropy secrets)
 * - Password: PBKDF2-SHA256 (slow, salted; suitable for human passwords)
 */
final class KeyDerivation
{
    /**
     * Derive a binary key from an application secret using HKDF-SHA256.
     *
     * @param string $secret High-entropy app secret.
     * @param int $keyBytes Desired output key length in bytes.
     * @param string $info HKDF "info" context string.
     *
     * @return string Binary key material of exactly $keyBytes length.
     */
    public static function deriveFromSecret(string $secret, int $keyBytes, string $info): string
    {
        return hash_hkdf('sha256', $secret, $keyBytes, $info, '');
    }

    /**
     * Derive a binary key from a password + salt using PBKDF2-SHA256.
     *
     * @param string $password Password input.
     * @param string $salt Binary salt.
     * @param int $keyBytes Desired output key length in bytes.
     * @param int $iterations PBKDF2 iteration count.
     *
     * @return string Binary key material.
     */
    public static function deriveFromPassword(string $password, string $salt, int $keyBytes, int $iterations): string
    {
        return hash_pbkdf2('sha256', $password, $salt, $iterations, $keyBytes, true);
    }

    /**
     * Generate cryptographically secure random bytes.
     *
     * @param int $length Number of bytes.
     *
     * @return string Binary random bytes.
     *
     * @throws \Exception If the CSPRNG fails.
     */
    public static function randomBytes(int $length): string
    {
        return random_bytes($length);
    }
}