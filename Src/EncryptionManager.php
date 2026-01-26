<?php

declare(strict_types=1);

namespace Temant\EncryptionManager;

use Temant\EncryptionManager\Contract\EncryptorInterface;
use Temant\EncryptionManager\Crypto\EncryptionCipher;
use Temant\EncryptionManager\Crypto\EncryptionConfig;
use Temant\EncryptionManager\Crypto\KeyDerivation;
use Temant\EncryptionManager\Crypto\Payload; 

/**
 * Modern authenticated encryptor using AES-GCM only.
 *
 * - App-secret mode: HKDF-derived key (fast; requires high-entropy secret)
 * - Password mode: PBKDF2-derived key + per-message random salt
 */
final class EncryptionManager implements EncryptorInterface
{
    /**
     * Cipher ID mapping for payload encoding/decoding.
     */
    private const int CIPHER_ID_AES_256_GCM = 1;
    private const int CIPHER_ID_AES_128_GCM = 2;

    /**
     * Encryption configuration.
     *
     * @var EncryptionConfig
     */
    private readonly EncryptionConfig $config;

    /**
     * Binary master key derived from the application secret for non-password mode.
     *
     * @var string
     */
    private string $masterKey;

    /**
     * Create a new manager.
     *
     * @param string $secret High-entropy application secret.
     * @param EncryptionConfig|null $config Optional configuration (defaults provided).
     *
     * @throws EncryptionException If OpenSSL cipher configuration is invalid.
     */
    public function __construct(string $secret, ?EncryptionConfig $config = null)
    {
        $this->config = $config ?? EncryptionConfig::defaults();

        // Validate IV length early.
        $this->config->cipher->ivLength();

        $this->masterKey = KeyDerivation::deriveFromSecret(
            secret: $secret,
            keyBytes: $this->config->cipher->keyLength(),
            info: $this->config->hkdfInfo
        );
    }

    /**
     * Rotate the application secret.
     *
     * @param string $newSecret New high-entropy application secret.
     */
    public function updateSecret(string $newSecret): void
    {
        $this->masterKey = KeyDerivation::deriveFromSecret(
            secret: $newSecret,
            keyBytes: $this->config->cipher->keyLength(),
            info: $this->config->hkdfInfo
        );
    }

    /**
     * {@inheritDoc}
     */
    public function encryptString(string $plaintext, ?string $password = null): string
    {
        $cipher = $this->config->cipher;
        $cipherId = $this->cipherToId($cipher);

        $salt = $password !== null
            ? KeyDerivation::randomBytes($this->config->saltBytes)
            : str_repeat("\0", $this->config->saltBytes);

        $iv = KeyDerivation::randomBytes($cipher->ivLength());

        $key = $password !== null
            ? KeyDerivation::deriveFromPassword(
                password: $password,
                salt: $salt,
                keyBytes: $cipher->keyLength(),
                iterations: $this->config->pbkdf2Iterations
            )
            : $this->masterKey;

        $tag = '';
        $ciphertext = openssl_encrypt(
            $plaintext,
            $cipher->value,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',
            $this->config->tagBytes
        ); 

        return (new Payload(
            cipherId: $cipherId,
            salt: $salt,
            iv: $iv,
            tag: $tag,
            ciphertext: $ciphertext
        ))->toString();
    }

    /**
     * {@inheritDoc}
     */
    public function decryptString(string $payload, ?string $password = null): string
    {
        $parsed = Payload::fromString($payload, $this->config);
        $cipher = $this->idToCipher($parsed->cipherId);

        // Enforce cipher match with configuration to avoid confusing mixed setups.
        // If you want cross-config decrypt (e.g. AES-128-GCM payloads) keep both ciphers allowed by config.
        if ($cipher !== $this->config->cipher) {
            throw EncryptionException::invalidPayload('Cipher mismatch for this manager configuration.');
        }

        if ($parsed->requiresPassword() && $password === null) {
            throw EncryptionException::invalidPayload('Password required but not provided.');
        }

        $key = $password !== null
            ? KeyDerivation::deriveFromPassword(
                password: $password,
                salt: $parsed->salt,
                keyBytes: $cipher->keyLength(),
                iterations: $this->config->pbkdf2Iterations
            )
            : $this->masterKey;

        $plaintext = openssl_decrypt(
            $parsed->ciphertext,
            $cipher->value,
            $key,
            OPENSSL_RAW_DATA,
            $parsed->iv,
            $parsed->tag,
            ''
        );

        if ($plaintext === false) {
            throw EncryptionException::openSslFailure('Decryption');
        }

        return $plaintext;
    }

    /**
     * {@inheritDoc}
     */
    public function encryptFile(string $inputFile, string $outputFile, ?string $password = null): void
    {
        $this->assertFileExists($inputFile);

        $data = @file_get_contents($inputFile);
        if ($data === false) {
            throw EncryptionException::fileReadFailed($inputFile);
        }

        $encrypted = $this->encryptString($data, $password);

        if (@file_put_contents($outputFile, $encrypted) === false) {
            throw EncryptionException::fileWriteFailed($outputFile);
        }
    }

    /**
     * {@inheritDoc}
     */
    public function decryptFile(string $inputFile, string $outputFile, ?string $password = null): void
    {
        $this->assertFileExists($inputFile);

        $data = @file_get_contents($inputFile);
        if ($data === false) {
            throw EncryptionException::fileReadFailed($inputFile);
        }

        $decrypted = $this->decryptString($data, $password);

        if (@file_put_contents($outputFile, $decrypted) === false) {
            throw EncryptionException::fileWriteFailed($outputFile);
        }
    }

    /**
     * Convert cipher enum to payload cipher ID.
     *
     * @param EncryptionCipher $cipher Cipher.
     *
     * @return int Cipher ID (1 byte).
     */
    private function cipherToId(EncryptionCipher $cipher): int
    {
        return match ($cipher) {
            EncryptionCipher::AES_256_GCM => self::CIPHER_ID_AES_256_GCM,
            EncryptionCipher::AES_128_GCM => self::CIPHER_ID_AES_128_GCM,
        };
    }

    /**
     * Convert payload cipher ID to cipher enum.
     *
     * @param int $id Payload cipher ID.
     *
     * @return EncryptionCipher Cipher.
     *
     * @throws EncryptionException If ID is unknown.
     */
    private function idToCipher(int $id): EncryptionCipher
    {
        return match ($id) {
            self::CIPHER_ID_AES_256_GCM => EncryptionCipher::AES_256_GCM,
            self::CIPHER_ID_AES_128_GCM => EncryptionCipher::AES_128_GCM,
            default => throw EncryptionException::invalidPayload('Unknown cipher id.'),
        };
    }

    /**
     * Ensure the given path exists and is a regular file.
     *
     * @param string $path File path.
     *
     * @throws EncryptionException If missing.
     */
    private function assertFileExists(string $path): void
    {
        if (!is_file($path)) {
            throw EncryptionException::fileNotFound($path);
        }
    }
}