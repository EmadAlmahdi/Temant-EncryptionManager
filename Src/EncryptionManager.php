<?php

declare(strict_types=1);

namespace Temant\EncryptionManager;

use Temant\EncryptionManager\Contract\EncryptorInterface;
use Temant\EncryptionManager\Crypto\EncryptionCipher;
use Temant\EncryptionManager\Crypto\EncryptionConfig;
use Temant\EncryptionManager\Crypto\KeyDerivation;
use Temant\EncryptionManager\Crypto\Payload;
use Temant\EncryptionManager\Crypto\StreamCipher;

/**
 * Modern authenticated encryptor using AES-GCM only.
 *
 * - App-secret mode: HKDF-derived key (fast; requires high-entropy secret)
 * - Password mode: PBKDF2-derived key + per-message random salt
 * - Key rotation: retired app secrets can still decrypt old payloads via a keyring
 * - Large files: {@see encryptStreamedFile()}/{@see decryptStreamedFile()} process files
 *   in fixed-size chunks instead of loading them fully into memory
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
     * Binary master keys derived from retired application secrets, most-recently-retired first.
     *
     * Tried, in order, when {@see $masterKey} fails to authenticate a payload, so data encrypted
     * under an older secret stays decryptable across a key rotation.
     *
     * @var list<string>
     */
    private array $retiredMasterKeys = [];

    /**
     * Create a new manager.
     *
     * @param string $secret High-entropy application secret.
     * @param EncryptionConfig|null $config Optional configuration (defaults provided).
     * @param list<string> $retiredSecrets Previously-used application secrets still allowed to
     *   decrypt (but never used to encrypt). Use this to bootstrap a keyring across requests/
     *   deployments, e.g. after a secret rotation. See also {@see updateSecret()}.
     */
    public function __construct(string $secret, ?EncryptionConfig $config = null, array $retiredSecrets = [])
    {
        $this->config = $config ?? EncryptionConfig::defaults();

        $this->masterKey = KeyDerivation::deriveFromSecret(
            secret: $secret,
            keyBytes: $this->config->cipher->keyLength(),
            info: $this->config->hkdfInfo
        );

        foreach ($retiredSecrets as $retiredSecret) {
            $this->retiredMasterKeys[] = KeyDerivation::deriveFromSecret(
                secret: $retiredSecret,
                keyBytes: $this->config->cipher->keyLength(),
                info: $this->config->hkdfInfo
            );
        }
    }

    /**
     * Rotate the application secret.
     *
     * @param string $newSecret New high-entropy application secret.
     * @param bool $retireCurrent When true (default), the current secret is kept in the keyring
     *   so payloads already encrypted under it remain decryptable. Pass false to immediately
     *   invalidate everything encrypted under the current secret.
     */
    public function updateSecret(string $newSecret, bool $retireCurrent = true): void
    {
        if ($retireCurrent) {
            array_unshift($this->retiredMasterKeys, $this->masterKey);
        }

        $this->masterKey = KeyDerivation::deriveFromSecret(
            secret: $newSecret,
            keyBytes: $this->config->cipher->keyLength(),
            info: $this->config->hkdfInfo
        );
    }

    /**
     * Add a retired application secret to the decryption keyring without changing the
     * secret used for new encryption.
     *
     * @param string $secret Previously-used application secret.
     */
    public function addRetiredSecret(string $secret): void
    {
        array_unshift($this->retiredMasterKeys, KeyDerivation::deriveFromSecret(
            secret: $secret,
            keyBytes: $this->config->cipher->keyLength(),
            info: $this->config->hkdfInfo
        ));
    }

    /**
     * Drop all retired secrets, permanently invalidating payloads that aren't
     * decryptable under the current secret.
     */
    public function clearRetiredSecrets(): void
    {
        $this->retiredMasterKeys = [];
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

        if ($ciphertext === false) {
            throw EncryptionException::openSslFailure('Encryption');
        }

        return new Payload($cipherId, $salt, $iv, $tag, $ciphertext)
            ->toString();
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

        if ($password !== null) {
            $key = KeyDerivation::deriveFromPassword(
                password: $password,
                salt: $parsed->salt,
                keyBytes: $cipher->keyLength(),
                iterations: $this->config->pbkdf2Iterations
            );

            $plaintext = openssl_decrypt($parsed->ciphertext, $cipher->value, $key, OPENSSL_RAW_DATA, $parsed->iv, $parsed->tag, '');
            if ($plaintext === false) {
                throw EncryptionException::openSslFailure('Decryption');
            }

            return $plaintext;
        }

        // No password: try the current app-secret key, then fall back through the
        // retired keyring so payloads survive a secret rotation.
        foreach ($this->candidateMasterKeys() as $candidate) {
            $plaintext = openssl_decrypt($parsed->ciphertext, $cipher->value, $candidate, OPENSSL_RAW_DATA, $parsed->iv, $parsed->tag, '');
            if ($plaintext !== false) {
                return $plaintext;
            }
        }

        throw EncryptionException::openSslFailure('Decryption');
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
     * Encrypt a file in fixed-size chunks, without loading it fully into memory.
     *
     * Unlike {@see encryptFile()}, the output is a binary chunked stream (see
     * {@see StreamCipher}), not a printable "v1:" payload, and files produced by one
     * cannot be decrypted by the other's counterpart. Prefer this for large files.
     *
     * @param string $inputFile Existing source file path.
     * @param string $outputFile Destination file path (overwritten if exists).
     * @param string|null $password Optional password for password-based encryption.
     * @param int $chunkSize Plaintext bytes per chunk. Defaults to {@see StreamCipher::DEFAULT_CHUNK_SIZE}.
     *
     * @throws EncryptionException If the input is missing, I/O fails, or $chunkSize is invalid.
     */
    public function encryptStreamedFile(
        string $inputFile,
        string $outputFile,
        ?string $password = null,
        int $chunkSize = StreamCipher::DEFAULT_CHUNK_SIZE
    ): void {
        if ($chunkSize < 1) {
            throw EncryptionException::invalidStream('Chunk size must be at least 1 byte.');
        }

        $this->assertFileExists($inputFile);

        $cipher = $this->config->cipher;
        $cipherId = $this->cipherToId($cipher);

        $salt = $password !== null
            ? KeyDerivation::randomBytes($this->config->saltBytes)
            : str_repeat("\0", $this->config->saltBytes);

        $key = $password !== null
            ? KeyDerivation::deriveFromPassword(
                password: $password,
                salt: $salt,
                keyBytes: $cipher->keyLength(),
                iterations: $this->config->pbkdf2Iterations
            )
            : $this->masterKey;

        $noncePrefix = KeyDerivation::randomBytes(StreamCipher::noncePrefixLength($cipher));

        $in = @fopen($inputFile, 'rb');
        if ($in === false) {
            throw EncryptionException::fileReadFailed($inputFile);
        }

        $out = @fopen($outputFile, 'wb');
        if ($out === false) {
            fclose($in);
            throw EncryptionException::fileWriteFailed($outputFile);
        }

        try {
            StreamCipher::writeHeader($out, $cipherId, $salt, $noncePrefix, $chunkSize);

            $counter = 0;
            $plainChunk = fread($in, $chunkSize);
            if ($plainChunk === false) {
                throw EncryptionException::fileReadFailed($inputFile);
            }

            while (true) {
                $isFinal = feof($in);

                $tag = '';
                $ciphertext = openssl_encrypt(
                    $plainChunk,
                    $cipher->value,
                    $key,
                    OPENSSL_RAW_DATA,
                    StreamCipher::buildNonce($noncePrefix, $counter, $isFinal),
                    $tag,
                    '',
                    $this->config->tagBytes
                );

                if ($ciphertext === false) {
                    throw EncryptionException::openSslFailure('Encryption');
                }

                StreamCipher::writeChunk($out, $ciphertext, $tag, $isFinal);

                if ($isFinal) {
                    break;
                }

                if (++$counter > 0xFFFFFFFF) {
                    throw EncryptionException::invalidStream('File too large: chunk counter overflow.');
                }

                $plainChunk = fread($in, $chunkSize);
                if ($plainChunk === false) {
                    throw EncryptionException::fileReadFailed($inputFile);
                }
            }
        } finally {
            fclose($in);
            fclose($out);
        }
    }

    /**
     * Decrypt a file previously produced by {@see encryptStreamedFile()}.
     *
     * @param string $inputFile Existing encrypted stream file path.
     * @param string $outputFile Destination plaintext file path (overwritten if exists).
     * @param string|null $password Optional password if the stream is password-encrypted.
     *
     * @throws EncryptionException If the input is missing, malformed, tampered with, or I/O fails.
     */
    public function decryptStreamedFile(string $inputFile, string $outputFile, ?string $password = null): void
    {
        $this->assertFileExists($inputFile);

        $in = @fopen($inputFile, 'rb');
        if ($in === false) {
            throw EncryptionException::fileReadFailed($inputFile);
        }

        $out = @fopen($outputFile, 'wb');
        if ($out === false) {
            fclose($in);
            throw EncryptionException::fileWriteFailed($outputFile);
        }

        try {
            $header = StreamCipher::readHeader($in, $this->config);
            $cipher = $this->idToCipher($header['cipherId']);

            if ($cipher !== $this->config->cipher) {
                throw EncryptionException::invalidPayload('Cipher mismatch for this manager configuration.');
            }

            $requiresPassword = $header['salt'] !== str_repeat("\0", $this->config->saltBytes);
            if ($requiresPassword && $password === null) {
                throw EncryptionException::invalidPayload('Password required but not provided.');
            }

            $key = $password !== null
                ? KeyDerivation::deriveFromPassword(
                    password: $password,
                    salt: $header['salt'],
                    keyBytes: $cipher->keyLength(),
                    iterations: $this->config->pbkdf2Iterations
                )
                : null;

            $counter = 0;
            $sawFinal = false;

            while (($chunk = StreamCipher::readChunk($in, $this->config->tagBytes)) !== null) {
                if ($sawFinal) {
                    throw EncryptionException::invalidStream('Unexpected data after final chunk.');
                }

                $nonce = StreamCipher::buildNonce($header['noncePrefix'], $counter, $chunk['isFinal']);

                if ($key !== null) {
                    $plaintext = openssl_decrypt($chunk['ciphertext'], $cipher->value, $key, OPENSSL_RAW_DATA, $nonce, $chunk['tag'], '');
                    if ($plaintext === false) {
                        throw EncryptionException::openSslFailure('Decryption');
                    }
                } else {
                    $plaintext = false;
                    foreach ($this->candidateMasterKeys() as $candidate) {
                        $plaintext = openssl_decrypt($chunk['ciphertext'], $cipher->value, $candidate, OPENSSL_RAW_DATA, $nonce, $chunk['tag'], '');
                        if ($plaintext !== false) {
                            // Cache the winning key so later chunks skip the trial loop.
                            $key = $candidate;
                            break;
                        }
                    }

                    if ($plaintext === false) {
                        throw EncryptionException::openSslFailure('Decryption');
                    }
                }

                if (fwrite($out, $plaintext) === false) {
                    throw EncryptionException::fileWriteFailed($outputFile);
                }

                $sawFinal = $chunk['isFinal'];
                $counter++;
            }

            if (!$sawFinal) {
                throw EncryptionException::invalidStream('Stream is truncated: no final chunk found.');
            }
        } finally {
            fclose($in);
            fclose($out);
        }
    }

    /**
     * Convert cipher enum to payload cipher ID.
     *
     * @param EncryptionCipher $cipher Cipher.
     *
     * @return int<0, 255> Cipher ID (1 byte).
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

    /**
     * Master keys to try for non-password decryption, current secret first followed by
     * the retired keyring (most-recently-retired first).
     *
     * @return iterable<string>
     */
    private function candidateMasterKeys(): iterable
    {
        yield $this->masterKey;
        yield from $this->retiredMasterKeys;
    }
}