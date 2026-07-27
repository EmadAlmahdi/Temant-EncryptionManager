<?php

declare(strict_types=1);

namespace Temant\EncryptionManager\Tests;

use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use Temant\EncryptionManager\Crypto\EncryptionCipher;
use Temant\EncryptionManager\Crypto\EncryptionConfig;
use Temant\EncryptionManager\Crypto\Payload;
use Temant\EncryptionManager\Crypto\StreamCipher;
use Temant\EncryptionManager\EncryptionException;
use Temant\EncryptionManager\EncryptionManager;

use function random_int;
use function chr;

/**
 * Test suite for {@see EncryptionManager}.
 */
final class EncryptionManagerTest extends TestCase
{
    public function testEncryptionConfigRejectsNonPositivePbkdf2Iterations(): void
    {
        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('pbkdf2Iterations must be at least 1');

        new EncryptionConfig(
            cipher: EncryptionCipher::AES_256_GCM,
            pbkdf2Iterations: 0,
            saltBytes: 16,
            tagBytes: 16,
            hkdfInfo: 'temant-encryption',
        );
    }

    public function testEncryptionConfigRejectsNonPositiveSaltBytes(): void
    {
        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('saltBytes must be at least 1');

        new EncryptionConfig(
            cipher: EncryptionCipher::AES_256_GCM,
            pbkdf2Iterations: 150_000,
            saltBytes: 0,
            tagBytes: 16,
            hkdfInfo: 'temant-encryption',
        );
    }

    public function testEncryptionConfigRejectsNonPositiveTagBytes(): void
    {
        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('tagBytes must be at least 1');

        new EncryptionConfig(
            cipher: EncryptionCipher::AES_256_GCM,
            pbkdf2Iterations: 150_000,
            saltBytes: 16,
            tagBytes: -1,
            hkdfInfo: 'temant-encryption',
        );
    }

    public function testRoundTripWithoutPassword(): void
    {
        $enc = new EncryptionManager('super-secret-app-key', EncryptionConfig::defaults());

        $plaintext = 'Hello 👋 ' . random_int(1, 1_000_000);
        $payload = $enc->encryptString($plaintext);

        self::assertNotSame($plaintext, $payload);
        self::assertSame($plaintext, $enc->decryptString($payload));
    }

    public function testRoundTripWithPassword(): void
    {
        $enc = new EncryptionManager('super-secret-app-key', EncryptionConfig::defaults());

        $plaintext = 'Sensitive ' . random_int(1, 1_000_000);
        $payload = $enc->encryptString($plaintext, 'user-password');

        self::assertSame($plaintext, $enc->decryptString($payload, 'user-password'));
    }

    public function testMissingVersionPrefixThrows(): void
    {
        $enc = new EncryptionManager('secret', EncryptionConfig::defaults());

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Missing version prefix');

        $enc->decryptString('not-a-versioned-payload');
    }

    public function testInvalidBase64Throws(): void
    {
        $enc = new EncryptionManager('secret', EncryptionConfig::defaults());

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Invalid base64');

        $enc->decryptString(Payload::VERSION_PREFIX . '!!!!notbase64!!!!');
    }

    public function testPayloadTooShortThrows(): void
    {
        $enc = new EncryptionManager('secret', EncryptionConfig::defaults());

        // base64 of single byte is still too short to contain required fields
        $tooShort = Payload::VERSION_PREFIX . base64_encode("\x01");

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Payload too short');

        $enc->decryptString($tooShort);
    }

    public function testUnknownCipherIdThrows(): void
    {
        $config = EncryptionConfig::defaults();
        $enc = new EncryptionManager('secret', $config);

        // Build a raw payload with an unknown cipher ID (e.g. 99) but correct minimum lengths.
        $cipherId = chr(99);
        $salt = str_repeat("\0", $config->saltBytes);
        $iv = str_repeat("\0", $config->cipher->ivLength());
        $tag = str_repeat("\0", $config->tagBytes);
        $ciphertext = "x"; // must be non-empty

        $raw = $cipherId . $salt . $iv . $tag . $ciphertext;
        $payload = Payload::VERSION_PREFIX . base64_encode($raw);

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Unknown cipher id');

        $enc->decryptString($payload);
    }

    public function testCipherMismatchForThisManagerConfigurationThrows(): void
    {
        $enc256 = new EncryptionManager(
            'secret',
            new EncryptionConfig(
                cipher: EncryptionCipher::AES_256_GCM,
                pbkdf2Iterations: 150_000,
                saltBytes: 16,
                tagBytes: 16,
                hkdfInfo: 'temant-encryption',
            )
        );

        $enc128 = new EncryptionManager(
            'secret',
            new EncryptionConfig(
                cipher: EncryptionCipher::AES_128_GCM,
                pbkdf2Iterations: 150_000,
                saltBytes: 16,
                tagBytes: 16,
                hkdfInfo: 'temant-encryption',
            )
        );

        $payload = $enc256->encryptString('hello');

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Cipher mismatch');

        $enc128->decryptString($payload);
    }

    public function testPasswordRequiredButNotProvidedThrows(): void
    {
        $enc = new EncryptionManager('secret', EncryptionConfig::defaults());

        $payload = $enc->encryptString('hello', 'pw');

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Password required');

        $enc->decryptString($payload, null);
    }

    public function testWrongPasswordFails(): void
    {
        $enc = new EncryptionManager('secret', EncryptionConfig::defaults());
        $payload = $enc->encryptString('hello', 'correct');

        $this->expectException(EncryptionException::class);

        $enc->decryptString($payload, 'wrong');
    }

    public function testTamperDetectionFails(): void
    {
        $enc = new EncryptionManager('secret', EncryptionConfig::defaults());
        $payload = $enc->encryptString('hello', 'pw');

        // Decode, flip one bit in ciphertext region, re-encode
        $raw = base64_decode(substr($payload, strlen(Payload::VERSION_PREFIX)), true);
        self::assertIsString($raw);

        // Flip last byte (ciphertext)
        $raw[strlen($raw) - 1] = $raw[strlen($raw) - 1] ^ "\x01";
        $tampered = Payload::VERSION_PREFIX . base64_encode($raw);

        $this->expectException(EncryptionException::class);

        $enc->decryptString($tampered, 'pw');
    }

    public function testUpdateSecretByDefaultKeepsOldPayloadDecryptable(): void
    {
        $enc = new EncryptionManager('old-secret', EncryptionConfig::defaults());
        $payload = $enc->encryptString('hello');

        $enc->updateSecret('new-secret');

        // Default rotation keeps the old key in the retired keyring.
        self::assertSame('hello', $enc->decryptString($payload));

        // New encryptions use the new secret.
        $newPayload = $enc->encryptString('world');
        self::assertSame('world', $enc->decryptString($newPayload));
    }

    public function testUpdateSecretWithRetireCurrentFalseInvalidatesOldPayload(): void
    {
        $enc = new EncryptionManager('old-secret', EncryptionConfig::defaults());
        $payload = $enc->encryptString('hello');

        $enc->updateSecret('new-secret', retireCurrent: false);

        $this->expectException(EncryptionException::class);

        $enc->decryptString($payload);
    }

    public function testConstructorAcceptsRetiredSecretsForDecryption(): void
    {
        $old = new EncryptionManager('old-secret', EncryptionConfig::defaults());
        $payload = $old->encryptString('hello');

        $new = new EncryptionManager('new-secret', EncryptionConfig::defaults(), retiredSecrets: ['old-secret']);

        self::assertSame('hello', $new->decryptString($payload));
    }

    public function testAddRetiredSecretAllowsDecryptingOldPayload(): void
    {
        $old = new EncryptionManager('old-secret', EncryptionConfig::defaults());
        $payload = $old->encryptString('hello');

        $new = new EncryptionManager('new-secret', EncryptionConfig::defaults());
        $new->addRetiredSecret('old-secret');

        self::assertSame('hello', $new->decryptString($payload));
    }

    public function testClearRetiredSecretsInvalidatesOldPayload(): void
    {
        $enc = new EncryptionManager('old-secret', EncryptionConfig::defaults());
        $payload = $enc->encryptString('hello');

        $enc->updateSecret('new-secret');
        self::assertSame('hello', $enc->decryptString($payload));

        $enc->clearRetiredSecrets();

        $this->expectException(EncryptionException::class);
        $enc->decryptString($payload);
    }

    public function testPayloadRequiresPasswordDetection(): void
    {
        $enc = new EncryptionManager('secret', EncryptionConfig::defaults());

        $payloadNoPw = $enc->encryptString('hello');
        $parsedNoPw = Payload::fromString($payloadNoPw, EncryptionConfig::defaults());
        self::assertFalse($parsedNoPw->requiresPassword());

        $payloadPw = $enc->encryptString('hello', 'pw');
        $parsedPw = Payload::fromString($payloadPw, EncryptionConfig::defaults());
        self::assertTrue($parsedPw->requiresPassword());
    }

    public function testEncryptFileAndDecryptFileRoundTrip(): void
    {
        $enc = new EncryptionManager('secret', EncryptionConfig::defaults());

        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'temant_enc_' . bin2hex(random_bytes(4));
        self::assertTrue(mkdir($dir) || is_dir($dir));

        $in = $dir . DIRECTORY_SEPARATOR . 'in.txt';
        $encFile = $dir . DIRECTORY_SEPARATOR . 'out.enc';
        $out = $dir . DIRECTORY_SEPARATOR . 'out.txt';

        $content = 'File test ' . random_int(1, 1_000_000);
        file_put_contents($in, $content);

        $enc->encryptFile($in, $encFile, 'pw');
        $enc->decryptFile($encFile, $out, 'pw');

        self::assertSame($content, (string) file_get_contents($out));
    }

    public function testEncryptFileThrowsWhenInputMissing(): void
    {
        $enc = new EncryptionManager('secret', EncryptionConfig::defaults());

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('File not found');

        $enc->encryptFile('/path/does/not/exist.txt', '/tmp/out.enc');
    }

    public function testDecryptFileThrowsWhenInputMissing(): void
    {
        $enc = new EncryptionManager('secret', EncryptionConfig::defaults());

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('File not found');

        $enc->decryptFile('/path/does/not/exist.enc', '/tmp/out.txt');
    }

    public function testEncryptFileThrowsWhenWriteFailsToNonExistentDirectory(): void
    {
        $enc = new EncryptionManager('secret', EncryptionConfig::defaults());

        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'temant_enc_' . bin2hex(random_bytes(4));
        self::assertTrue(mkdir($dir) || is_dir($dir));

        $in = $dir . DIRECTORY_SEPARATOR . 'in.txt';
        file_put_contents($in, 'hello');

        $badOut = $dir . DIRECTORY_SEPARATOR . 'no_such_dir' . DIRECTORY_SEPARATOR . 'out.enc';

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Failed to write file');

        $enc->encryptFile($in, $badOut);
    }

    public function testDecryptFileThrowsWhenWriteFailsToNonExistentDirectory(): void
    {
        $enc = new EncryptionManager('secret', EncryptionConfig::defaults());

        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'temant_enc_' . bin2hex(random_bytes(4));
        self::assertTrue(mkdir($dir) || is_dir($dir));

        $encFile = $dir . DIRECTORY_SEPARATOR . 'out.enc';
        file_put_contents($encFile, $enc->encryptString('hello'));

        $badOut = $dir . DIRECTORY_SEPARATOR . 'no_such_dir' . DIRECTORY_SEPARATOR . 'out.txt';

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Failed to write file');

        $enc->decryptFile($encFile, $badOut);
    }

    public function testCipherIdMappingCoversAes128Arm(): void
    {
        $enc128 = new EncryptionManager(
            'secret',
            new EncryptionConfig(
                cipher: EncryptionCipher::AES_128_GCM,
                pbkdf2Iterations: 150_000,
                saltBytes: 16,
                tagBytes: 16,
                hkdfInfo: 'temant-encryption',
            )
        );

        $payload = $enc128->encryptString('hello');
        self::assertSame('hello', $enc128->decryptString($payload));
    }

    public function testCollectOpenSslErrorsAggregatesErrors(): void
    {
        $provider = new FakeOpenSslErrorProvider([
            'error one',
            'error two',
        ]);

        $ref = new ReflectionMethod(
            EncryptionException::class,
            'collectOpenSslErrors'
        );

        $result = $ref->invoke(null, $provider);

        self::assertSame('error one | error two', $result);
    }

    public function testFileReadFailedUsingVfsStream(): void
    {
        $root = vfsStream::setup('root');

        // Create file and make it unreadable
        $file = vfsStream::newFile('input.txt', 0000)
            ->at($root)
            ->setContent('secret');

        $enc = new EncryptionManager('secret');

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Failed to read file');

        $enc->encryptFile(
            vfsStream::url('root/input.txt'),
            vfsStream::url('root/output.enc')
        );
    }

    public function testFileWriteFailedUsingVfsStream(): void
    {
        $root = vfsStream::setup('root');

        // Readable input
        vfsStream::newFile('input.txt', 0444)
            ->at($root)
            ->setContent('data');

        // Output directory not writable
        vfsStream::newDirectory('out', 0444)->at($root);

        $enc = new EncryptionManager('secret');

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Failed to write file');

        $enc->encryptFile(
            vfsStream::url('root/input.txt'),
            vfsStream::url('root/out/output.enc')
        );
    }

    public function testDecryptFileReadFailedUsingVfsStream(): void
    {
        $root = vfsStream::setup('root');

        // Create file and make it unreadable
        $file = vfsStream::newFile('input.enc', 0000)
            ->at($root)
            ->setContent('encrypted-data');

        $enc = new EncryptionManager('secret');

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Failed to read file');

        $enc->decryptFile(
            vfsStream::url('root/input.enc'),
            vfsStream::url('root/output.txt')
        );
    }

    public function testDecryptFileWriteFailedUsingVfsStream(): void
    {
        $root = vfsStream::setup('root');

        // Readable encrypted input
        $enc = new EncryptionManager('secret');
        $payload = $enc->encryptString('data');

        vfsStream::newFile('input.enc', 0444)
            ->at($root)
            ->setContent($payload);

        // Output directory not writable
        vfsStream::newDirectory('out', 0444)->at($root);

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Failed to write file');

        $enc->decryptFile(
            vfsStream::url('root/input.enc'),
            vfsStream::url('root/out/output.txt')
        );
    }

    private function tempDir(): string
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'temant_enc_' . bin2hex(random_bytes(4));
        self::assertTrue(mkdir($dir) || is_dir($dir));

        return $dir;
    }

    public function testStreamedFileRoundTripWithoutPassword(): void
    {
        $enc = new EncryptionManager('secret', EncryptionConfig::defaults());
        $dir = $this->tempDir();

        $in = $dir . DIRECTORY_SEPARATOR . 'in.txt';
        $encFile = $dir . DIRECTORY_SEPARATOR . 'out.enc';
        $out = $dir . DIRECTORY_SEPARATOR . 'out.txt';

        // Force many chunks with a tiny chunk size.
        $content = str_repeat('Streamed content chunk. ', 1000);
        file_put_contents($in, $content);

        $enc->encryptStreamedFile($in, $encFile, chunkSize: 16);
        $enc->decryptStreamedFile($encFile, $out);

        self::assertSame($content, (string) file_get_contents($out));
    }

    public function testStreamedFileRoundTripWithPassword(): void
    {
        $enc = new EncryptionManager('secret', EncryptionConfig::defaults());
        $dir = $this->tempDir();

        $in = $dir . DIRECTORY_SEPARATOR . 'in.txt';
        $encFile = $dir . DIRECTORY_SEPARATOR . 'out.enc';
        $out = $dir . DIRECTORY_SEPARATOR . 'out.txt';

        $content = 'Sensitive streamed content ' . random_int(1, 1_000_000);
        file_put_contents($in, $content);

        $enc->encryptStreamedFile($in, $encFile, 'pw', chunkSize: 8);
        $enc->decryptStreamedFile($encFile, $out, 'pw');

        self::assertSame($content, (string) file_get_contents($out));
    }

    public function testStreamedFileRoundTripEmptyFile(): void
    {
        $enc = new EncryptionManager('secret', EncryptionConfig::defaults());
        $dir = $this->tempDir();

        $in = $dir . DIRECTORY_SEPARATOR . 'in.txt';
        $encFile = $dir . DIRECTORY_SEPARATOR . 'out.enc';
        $out = $dir . DIRECTORY_SEPARATOR . 'out.txt';

        file_put_contents($in, '');

        $enc->encryptStreamedFile($in, $encFile);
        $enc->decryptStreamedFile($encFile, $out);

        self::assertSame('', (string) file_get_contents($out));
    }

    public function testStreamedFileUsesKeyRotationKeyring(): void
    {
        $old = new EncryptionManager('old-secret', EncryptionConfig::defaults());
        $dir = $this->tempDir();

        $in = $dir . DIRECTORY_SEPARATOR . 'in.txt';
        $encFile = $dir . DIRECTORY_SEPARATOR . 'out.enc';
        $out = $dir . DIRECTORY_SEPARATOR . 'out.txt';

        file_put_contents($in, str_repeat('rotate me ', 100));
        $old->encryptStreamedFile($in, $encFile, chunkSize: 32);

        $new = new EncryptionManager('new-secret', EncryptionConfig::defaults(), retiredSecrets: ['old-secret']);
        $new->decryptStreamedFile($encFile, $out);

        self::assertSame(file_get_contents($in), file_get_contents($out));
    }

    public function testStreamedFileTamperedChunkFailsAuthentication(): void
    {
        $enc = new EncryptionManager('secret', EncryptionConfig::defaults());
        $dir = $this->tempDir();

        $in = $dir . DIRECTORY_SEPARATOR . 'in.txt';
        $encFile = $dir . DIRECTORY_SEPARATOR . 'out.enc';
        $out = $dir . DIRECTORY_SEPARATOR . 'out.txt';

        file_put_contents($in, str_repeat('tamper test ', 50));
        $enc->encryptStreamedFile($in, $encFile, chunkSize: 16);

        $raw = (string) file_get_contents($encFile);
        $raw[strlen($raw) - 1] = $raw[strlen($raw) - 1] ^ "\x01";
        file_put_contents($encFile, $raw);

        $this->expectException(EncryptionException::class);
        $enc->decryptStreamedFile($encFile, $out);
    }

    public function testStreamedFileTruncatedStreamThrows(): void
    {
        $enc = new EncryptionManager('secret', EncryptionConfig::defaults());
        $dir = $this->tempDir();

        $in = $dir . DIRECTORY_SEPARATOR . 'in.txt';
        $encFile = $dir . DIRECTORY_SEPARATOR . 'out.enc';
        $out = $dir . DIRECTORY_SEPARATOR . 'out.txt';

        file_put_contents($in, str_repeat('truncate me ', 50));
        $enc->encryptStreamedFile($in, $encFile, chunkSize: 16);

        $raw = (string) file_get_contents($encFile);
        file_put_contents($encFile, substr($raw, 0, (int) (strlen($raw) / 2)));

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Invalid stream');
        $enc->decryptStreamedFile($encFile, $out);
    }

    public function testStreamedFileMissingFinalChunkThrows(): void
    {
        $enc = new EncryptionManager('secret', EncryptionConfig::defaults());
        $dir = $this->tempDir();

        $in = $dir . DIRECTORY_SEPARATOR . 'in.txt';
        $encFile = $dir . DIRECTORY_SEPARATOR . 'out.enc';
        $out = $dir . DIRECTORY_SEPARATOR . 'out.txt';

        // 100 bytes with a 16-byte chunk size: six full 16-byte chunks, then a final 4-byte chunk.
        file_put_contents($in, str_repeat('x', 100));
        $enc->encryptStreamedFile($in, $encFile, chunkSize: 16);

        $raw = (string) file_get_contents($encFile);

        // Drop the final chunk on disk: 1 (isFinal) + 4 (length) + 16 (tag, GCM default) + 4 (ciphertext).
        $finalChunkOnDiskSize = 1 + 4 + 16 + 4;
        file_put_contents($encFile, substr($raw, 0, -$finalChunkOnDiskSize));

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Stream is truncated');
        $enc->decryptStreamedFile($encFile, $out);
    }

    public function testStreamedFileCipherMismatchThrows(): void
    {
        $enc256 = new EncryptionManager(
            'secret',
            new EncryptionConfig(
                cipher: EncryptionCipher::AES_256_GCM,
                pbkdf2Iterations: 150_000,
                saltBytes: 16,
                tagBytes: 16,
                hkdfInfo: 'temant-encryption',
            )
        );

        $enc128 = new EncryptionManager(
            'secret',
            new EncryptionConfig(
                cipher: EncryptionCipher::AES_128_GCM,
                pbkdf2Iterations: 150_000,
                saltBytes: 16,
                tagBytes: 16,
                hkdfInfo: 'temant-encryption',
            )
        );

        $dir = $this->tempDir();
        $in = $dir . DIRECTORY_SEPARATOR . 'in.txt';
        $encFile = $dir . DIRECTORY_SEPARATOR . 'out.enc';
        $out = $dir . DIRECTORY_SEPARATOR . 'out.txt';

        file_put_contents($in, 'hello');
        $enc256->encryptStreamedFile($in, $encFile);

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Cipher mismatch');
        $enc128->decryptStreamedFile($encFile, $out);
    }

    public function testStreamedFilePasswordRequiredButNotProvidedThrows(): void
    {
        $enc = new EncryptionManager('secret', EncryptionConfig::defaults());
        $dir = $this->tempDir();

        $in = $dir . DIRECTORY_SEPARATOR . 'in.txt';
        $encFile = $dir . DIRECTORY_SEPARATOR . 'out.enc';
        $out = $dir . DIRECTORY_SEPARATOR . 'out.txt';

        file_put_contents($in, 'hello');
        $enc->encryptStreamedFile($in, $encFile, 'pw');

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Password required');
        $enc->decryptStreamedFile($encFile, $out);
    }

    public function testEncryptStreamedFileThrowsWhenInputMissing(): void
    {
        $enc = new EncryptionManager('secret', EncryptionConfig::defaults());

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('File not found');

        $enc->encryptStreamedFile('/path/does/not/exist.txt', '/tmp/out.enc');
    }

    public function testEncryptStreamedFileThrowsOnInvalidChunkSize(): void
    {
        $enc = new EncryptionManager('secret', EncryptionConfig::defaults());
        $dir = $this->tempDir();
        $in = $dir . DIRECTORY_SEPARATOR . 'in.txt';
        file_put_contents($in, 'hello');

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Chunk size must be at least 1 byte');

        $enc->encryptStreamedFile($in, $dir . DIRECTORY_SEPARATOR . 'out.enc', chunkSize: 0);
    }

    public function testDecryptStreamedFileThrowsOnInvalidHeaderChunkSize(): void
    {
        $enc = new EncryptionManager('secret', EncryptionConfig::defaults());
        $dir = $this->tempDir();
        $encFile = $dir . DIRECTORY_SEPARATOR . 'bad.enc';
        $out = $dir . DIRECTORY_SEPARATOR . 'out.txt';

        // A well-formed header (default config: 16-byte salt, 7-byte nonce prefix) but chunkSize = 0.
        $header = StreamCipher::MAGIC . chr(1) . str_repeat("\0", 16) . str_repeat("\0", 7) . pack('N', 0);
        file_put_contents($encFile, $header);

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Invalid chunk size');

        $enc->decryptStreamedFile($encFile, $out);
    }

    public function testDecryptStreamedFileThrowsOnBadMagic(): void
    {
        $enc = new EncryptionManager('secret', EncryptionConfig::defaults());
        $dir = $this->tempDir();
        $encFile = $dir . DIRECTORY_SEPARATOR . 'bad.enc';
        $out = $dir . DIRECTORY_SEPARATOR . 'out.txt';
        file_put_contents($encFile, 'not-a-stream-file-at-all');

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Missing or unknown stream magic');

        $enc->decryptStreamedFile($encFile, $out);
    }
}