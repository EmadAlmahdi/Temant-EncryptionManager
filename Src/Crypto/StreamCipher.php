<?php

declare(strict_types=1);

namespace Temant\EncryptionManager\Crypto;

use Temant\EncryptionManager\EncryptionException;

use function chr;
use function fread;
use function fwrite;
use function ord;
use function pack;
use function strlen;
use function unpack;

/**
 * Binary framing for chunked (streaming) AEAD encryption of large files.
 *
 * Nonce construction follows the STREAM approach (Hoang/Reyhanitabar/Rogaway/Vizar):
 *
 *   nonce = noncePrefix (random, fixed per file) || chunkCounter (4 bytes BE) || isFinal (1 byte)
 *
 * Binding the chunk index and "is this the last chunk" flag into the nonce means the GCM
 * authentication tag implicitly covers chunk position and finality: reordering, duplicating,
 * dropping, or truncating chunks changes the nonce a chunk was (or should have been) encrypted
 * under, so tampering surfaces as an authentication failure rather than silently-wrong plaintext.
 *
 * File layout:
 *   magic (4 bytes) "TSS1"
 *   cipherId (1 byte)
 *   salt (saltBytes bytes; zero-filled when not in password mode)
 *   noncePrefix (ivLength - 5 bytes)
 *   chunkSize (4 bytes BE; plaintext bytes per chunk, informational only)
 *   repeated chunks:
 *     isFinal (1 byte: 0x00 or 0x01)
 *     ciphertextLength (4 bytes BE)
 *     tag (tagBytes bytes)
 *     ciphertext (ciphertextLength bytes)
 */
final class StreamCipher
{
    public const string MAGIC = 'TSS1';

    public const int DEFAULT_CHUNK_SIZE = 65536;

    private function __construct()
    {
    }

    /**
     * Number of random per-file bytes used in the nonce prefix for a given cipher.
     *
     * @return int<1, max>
     */
    public static function noncePrefixLength(EncryptionCipher $cipher): int
    {
        return $cipher->ivLength() - 5;
    }

    /**
     * Build the 12-byte GCM nonce for a single chunk.
     */
    public static function buildNonce(string $noncePrefix, int $counter, bool $isFinal): string
    {
        return $noncePrefix . pack('N', $counter) . ($isFinal ? "\x01" : "\x00");
    }

    /**
     * @param resource $stream
     * @param int<0, 255> $cipherId
     */
    public static function writeHeader($stream, int $cipherId, string $salt, string $noncePrefix, int $chunkSize): void
    {
        self::write($stream, self::MAGIC . chr($cipherId) . $salt . $noncePrefix . pack('N', $chunkSize));
    }

    /**
     * @param resource $stream
     * @return array{cipherId: int, salt: string, noncePrefix: string, chunkSize: int}
     */
    public static function readHeader($stream, EncryptionConfig $config): array
    {
        if (self::read($stream, 4) !== self::MAGIC) {
            throw EncryptionException::invalidStream('Missing or unknown stream magic.');
        }

        $cipherId = ord(self::read($stream, 1));
        $salt = self::read($stream, $config->saltBytes);
        $noncePrefix = self::read($stream, self::noncePrefixLength($config->cipher));

        /** @var array{1: int} $unpacked */
        $unpacked = unpack('N', self::read($stream, 4));
        $chunkSize = $unpacked[1];

        if ($chunkSize < 1) {
            throw EncryptionException::invalidStream('Invalid chunk size in stream header.');
        }

        return [
            'cipherId' => $cipherId,
            'salt' => $salt,
            'noncePrefix' => $noncePrefix,
            'chunkSize' => $chunkSize,
        ];
    }

    /**
     * @param resource $stream
     */
    public static function writeChunk($stream, string $ciphertext, string $tag, bool $isFinal): void
    {
        self::write($stream, ($isFinal ? "\x01" : "\x00") . pack('N', strlen($ciphertext)) . $tag . $ciphertext);
    }

    /**
     * Read one chunk's framing and body.
     *
     * @param resource $stream
     * @param int<1, max> $tagBytes
     * @return array{isFinal: bool, ciphertext: string, tag: string}|null Null at a clean end of stream
     *   (i.e. no more bytes at all, right on a chunk boundary).
     */
    public static function readChunk($stream, int $tagBytes): ?array
    {
        $flag = fread($stream, 1);
        if ($flag === false || $flag === '') {
            return null;
        }

        /** @var array{1: int} $unpacked */
        $unpacked = unpack('N', self::read($stream, 4));
        $ciphertextLength = $unpacked[1];

        $tag = self::read($stream, $tagBytes);
        $ciphertext = $ciphertextLength > 0 ? self::read($stream, $ciphertextLength) : '';

        return [
            'isFinal' => $flag === "\x01",
            'ciphertext' => $ciphertext,
            'tag' => $tag,
        ];
    }

    /**
     * @param resource $stream
     * @param int<1, max> $length
     */
    private static function read($stream, int $length): string
    {
        $data = fread($stream, $length);
        if ($data === false || strlen($data) !== $length) {
            throw EncryptionException::invalidStream('Unexpected end of stream.');
        }

        return $data;
    }

    /**
     * @param resource $stream
     */
    private static function write($stream, string $data): void
    {
        if (fwrite($stream, $data) === false) {
            throw EncryptionException::invalidStream('Failed to write to stream.');
        }
    }
}
