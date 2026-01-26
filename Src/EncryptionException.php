<?php

declare(strict_types=1);

namespace Temant\EncryptionManager;

use RuntimeException;
use Temant\EncryptionManager\Contract\OpenSslErrorProviderInterface;
use Temant\EncryptionManager\Crypto\NativeOpenSslErrorProvider;

/**
 * Domain exception for encryption/decryption failures.
 *
 * Thrown for:
 * - invalid payload formats (bad base64, wrong version, inconsistent sizes)
 * - cipher configuration problems
 * - OpenSSL encryption/decryption errors
 * - file IO errors
 */
final class EncryptionException extends RuntimeException
{
    /**
     * Create an exception for an invalid payload.
     *
     * @param string $reason Human-readable reason for why payload is invalid.
     */
    public static function invalidPayload(string $reason): self
    {
        return new self("Invalid payload: $reason");
    }

    /**
     * Create an exception for an OpenSSL failure.
     *
     * @param string $operation Operation name, e.g. "Encryption" or "Decryption".
     */
    public static function openSslFailure(string $operation): self
    {
        $errors = self::collectOpenSslErrors();
        $suffix = $errors !== '' ? (" OpenSSL: $errors") : '';

        return new self("$operation failed.$suffix");
    }

    /**
     * Create an exception for missing files.
     *
     * @param string $path Path that was expected to exist.
     */
    public static function fileNotFound(string $path): self
    {
        return new self("File not found: $path");
    }

    /**
     * Create an exception for file read failure.
     *
     * @param string $path File that failed to read.
     */
    public static function fileReadFailed(string $path): self
    {
        return new self("Failed to read file: $path");
    }

    /**
     * Create an exception for file write failure.
     *
     * @param string $path File that failed to write.
     */
    public static function fileWriteFailed(string $path): self
    {
        return new self("Failed to write file: $path");
    }

    /**
     * Drain OpenSSL error queue and return a combined message.
     * @param OpenSslErrorProviderInterface|null $provider Optional error provider for testing.
     * @return string Pipe-separated error messages or empty string.
     */
    private static function collectOpenSslErrors(?OpenSslErrorProviderInterface $provider = null): string
    {
        $provider ??= new NativeOpenSslErrorProvider();

        $errors = [];

        while (($e = $provider->nextError()) !== false) {
            $errors[] = $e;
        }

        return implode(' | ', $errors);
    }
}