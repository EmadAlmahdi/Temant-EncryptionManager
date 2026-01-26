<?php

declare(strict_types=1);

namespace Temant\EncryptionManager\Contract;

/**
 * Public contract for an encryptor/decryptor.
 *
 * Implementations must provide authenticated encryption (AEAD).
 */
interface EncryptorInterface
{
    /**
     * Encrypt plaintext into a portable, printable payload.
     *
     * If $password is provided, a per-message salt MUST be used and the encryption key MUST be
     * derived from the password using a password-based KDF.
     *
     * @param string $plaintext Plaintext input.
     * @param string|null $password Optional password for password-based encryption.
     *
     * @return string Versioned payload string.
     */
    public function encryptString(string $plaintext, ?string $password = null): string;

    /**
     * Decrypt a payload previously produced by {@see encryptString()}.
     *
     * If $password is required by the payload, callers must provide it.
     *
     * @param string $payload Versioned payload string.
     * @param string|null $password Optional password if payload is password-encrypted.
     *
     * @return string Decrypted plaintext.
     */
    public function decryptString(string $payload, ?string $password = null): string;

    /**
     * Encrypt the contents of a file.
     *
     * @param string $inputFile Existing source file path.
     * @param string $outputFile Destination file path (overwritten if exists).
     * @param string|null $password Optional password for password-based encryption.
     */
    public function encryptFile(string $inputFile, string $outputFile, ?string $password = null): void;

    /**
     * Decrypt the contents of a file containing a versioned payload.
     *
     * @param string $inputFile Existing encrypted file path.
     * @param string $outputFile Destination plaintext file path (overwritten if exists).
     * @param string|null $password Optional password if payload is password-encrypted.
     */
    public function decryptFile(string $inputFile, string $outputFile, ?string $password = null): void;
}