<?php

declare(strict_types=1);

namespace Temant\EncryptionManager\Crypto;

use Temant\EncryptionManager\EncryptionException;

use function chr;
use function ord;
use function strlen;
use function str_repeat;
use function str_starts_with;
use function substr;
use function base64_encode;
use function base64_decode;

/**
 * Value object representing an encrypted payload.
 *
 * The payload is a versioned printable string:
 *   "v1:" + base64(raw)
 *
 * Raw binary layout:
 * - 1 byte: cipherId
 * - saltBytes bytes: salt (all zero if password mode not used)
 * - ivLength bytes: iv
 * - tagBytes bytes: tag
 * - remaining bytes: ciphertext
 */
final class Payload
{
    /**
     * Version prefix used in the string representation.
     */
    public const string VERSION_PREFIX = 'v1:';

    /**
     * @param int<0, 255> $cipherId Cipher ID.
     * @param string $salt Binary salt (saltBytes length).
     * @param string $iv Binary IV.
     * @param string $tag Binary auth tag (tagBytes length).
     * @param string $ciphertext Binary ciphertext.
     */
    public function __construct(
        public readonly int $cipherId,
        public readonly string $salt,
        public readonly string $iv,
        public readonly string $tag,
        public readonly string $ciphertext,
    ) {
    }

    /**
     * Encode this payload into a versioned printable string.
     *
     * @return string Versioned payload string.
     */
    public function toString(): string
    {
        $raw = chr($this->cipherId) . $this->salt . $this->iv . $this->tag . $this->ciphertext;
        return self::VERSION_PREFIX . base64_encode($raw);
    }

    /**
     * Parse a payload string into a {@see Payload} object.
     *
     * @param string $payloadString Versioned payload string.
     * @param EncryptionConfig $config Config used to validate sizes.
     *
     * @return self Parsed payload object.
     *
     * @throws EncryptionException If version/base64/layout is invalid.
     */
    public static function fromString(string $payloadString, EncryptionConfig $config): self
    {
        if (!str_starts_with($payloadString, self::VERSION_PREFIX)) {
            throw EncryptionException::invalidPayload('Missing version prefix.');
        }

        $b64 = substr($payloadString, strlen(self::VERSION_PREFIX));
        $raw = base64_decode($b64, true);

        if ($raw === false) {
            throw EncryptionException::invalidPayload('Invalid base64 encoding.');
        }

        $min = 1 + $config->saltBytes + $config->cipher->ivLength() + $config->tagBytes + 1;
        if (strlen($raw) < $min) {
            throw EncryptionException::invalidPayload('Payload too short.');
        }

        $cipherId = ord($raw[0]);
        $offset = 1;

        $salt = substr($raw, $offset, $config->saltBytes);
        $offset += $config->saltBytes;

        $ivLen = $config->cipher->ivLength();
        $iv = substr($raw, $offset, $ivLen);
        $offset += $ivLen;

        $tag = substr($raw, $offset, $config->tagBytes);
        $offset += $config->tagBytes;

        $ciphertext = substr($raw, $offset);

        if (strlen($salt) !== $config->saltBytes) {
            throw EncryptionException::invalidPayload('Salt length mismatch.');
        }

        if (strlen($iv) !== $ivLen) {
            throw EncryptionException::invalidPayload('IV length mismatch.');
        }

        if (strlen($tag) !== $config->tagBytes) {
            throw EncryptionException::invalidPayload('Tag length mismatch.');
        }

        if ($ciphertext === '') {
            throw EncryptionException::invalidPayload('Ciphertext is empty.');
        }

        return new self($cipherId, $salt, $iv, $tag, $ciphertext);
    }

    /**
     * Determine whether this payload indicates password mode.
     *
     * Password mode is indicated by a non-zero salt.
     *
     * @return bool True if salt is not all zero bytes.
     */
    public function requiresPassword(): bool
    {
        return $this->salt !== str_repeat("\0", strlen($this->salt));
    }
}
