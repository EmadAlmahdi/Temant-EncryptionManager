<?php declare(strict_types=1);

namespace Temant\Encrypter\Tests {

    use Temant\EncryptionManager\EncryptionManager;
    use Temant\EncryptionManager\Exception\EncryptionException;
    use Temant\EncryptionManager\EncryptionTypeEnum;
    use PHPUnit\Framework\TestCase;

    /**
     * Test suite for the Encryption class.
     */
    class EncryptionTest extends TestCase
    {
        private EncryptionManager $encryption;

        /**
         * Sets up the encryption instance before each test.
         *
         * @return void
         */
        protected function setUp(): void
        {
            parent::setUp();
            $this->encryption = new EncryptionManager('test-key', EncryptionTypeEnum::BYTES_256);
        }

        /**
         * Tests the updateKey method.
         *
         * @return void
         */
        public function testUpdateKey(): void
        {
            $oldKey = $this->encryption->getKey();
            $this->encryption->updateKey('new-test-key');
            $newKey = $this->encryption->getKey();

            $this->assertNotEquals($oldKey, $newKey);
        } 

        /**
         * Tests the getKey method.
         *
         * @return void
         */
        public function testGetKey(): void
        {
            $key = $this->encryption->getKey();
            $this->assertIsString($key);
            $this->assertNotEmpty($key);
        }

        /**
         * Tests the getIvLength method.
         *
         * @return void
         */
        public function testGetIvLength(): void
        {
            $ivLength = $this->encryption->getIvLength();
            $this->assertIsInt($ivLength);
            $this->assertGreaterThan(0, $ivLength);
        }

        /**
         * Tests encryption of a string without a password.
         *
         * @return void
         */
        public function testEncryptStringWithoutPassword(): void
        {
            $plainText = 'Hello, World!';
            $encrypted = $this->encryption->encryptString($plainText);

            $this->assertNotEquals($plainText, $encrypted);
            $this->assertStringContainsString('=', $encrypted); // Base64 encoded string
        }

        /**
         * Tests decryption of a string encrypted without a password.
         *
         * @return void
         */
        public function testDecryptStringWithoutPassword(): void
        {
            $plainText = 'Hello, World!';
            $encrypted = $this->encryption->encryptString($plainText);
            $decrypted = $this->encryption->decryptString($encrypted);

            $this->assertEquals($plainText, $decrypted);
        }

        /**
         * Tests encryption and decryption of a string with a password.
         *
         * @return void
         */
        public function testEncryptDecryptStringWithPassword(): void
        {
            $plainText = 'Hello, World!';
            $password = 'secure-password';
            $encrypted = $this->encryption->encryptString($plainText, $password);
            $decrypted = $this->encryption->decryptString($encrypted, $password);

            $this->assertEquals($plainText, $decrypted);
        }

        /**
         * Tests file encryption and decryption with a password.
         *
         * @return void
         */
        public function testFileEncryptionAndDecryption(): void
        {
            $plainText = 'This is a test file content.';
            $inputFile = 'test-input.txt';
            $outputFile = 'test-output.txt';
            $password = 'file-password';

            file_put_contents($inputFile, $plainText);

            $this->encryption->encryptFile($inputFile, 'test-encrypted.txt', $password);
            $this->encryption->decryptFile('test-encrypted.txt', $outputFile, $password);

            $decryptedContent = file_get_contents($outputFile);

            $this->assertEquals($plainText, $decryptedContent);

            // Cleanup
            unlink($inputFile);
            unlink('test-encrypted.txt');
            unlink($outputFile);
        }

        /**
         * Tests file encryption without a password.
         *
         * @return void
         */
        public function testEncryptFileWithoutPassword(): void
        {
            $plainText = 'This is another test file content.';
            $inputFile = 'test-input-no-pass.txt';
            $outputFile = 'test-encrypted-no-pass.txt';

            file_put_contents($inputFile, $plainText);

            $this->encryption->encryptFile($inputFile, $outputFile);

            $this->assertFileExists($outputFile);

            // Cleanup
            unlink($inputFile);
            unlink($outputFile);
        }

        /**
         * Tests file decryption without a password.
         *
         * @return void
         */
        public function testDecryptFileWithoutPassword(): void
        {
            $plainText = 'This is yet another test file content.';
            $inputFile = 'test-input-no-pass.txt';
            $outputFile = 'test-decrypted-no-pass.txt';

            file_put_contents($inputFile, $plainText);
            $this->encryption->encryptFile($inputFile, 'test-encrypted-no-pass.txt');

            $this->encryption->decryptFile('test-encrypted-no-pass.txt', $outputFile);

            $decryptedContent = file_get_contents($outputFile);

            $this->assertEquals($plainText, $decryptedContent);

            // Cleanup
            unlink($inputFile);
            unlink('test-encrypted-no-pass.txt');
            unlink($outputFile);
        }

        /**
         * Tests handling of decryption failure due to incorrect password.
         *
         * @return void
         */
        public function testDecryptStringFailureDueToIncorrectPassword(): void
        {
            $this->expectException(EncryptionException::class);

            $plainText = 'Hello, World!';
            $password = 'secure-password';
            $encrypted = $this->encryption->encryptString($plainText, $password);

            // Simulate decryption failure by using a wrong password
            $this->encryption->decryptString($encrypted, 'wrong-password');
        }

        /**
         * Tests handling of decryption failure due to incorrect encrypted data.
         *
         * @return void
         */
        public function testDecryptStringFailureDueToCorruptedData(): void
        {
            $this->expectException(EncryptionException::class);

            $corruptedData = 'corrupted-data';
            $this->encryption->decryptString($corruptedData);
        }

        /**
         * Tests handling of invalid files for encryption.
         *
         * @return void
         */
        public function testInvalidFileForEncryption(): void
        {
            $this->expectException(EncryptionException::class);
            $this->encryption->encryptFile('nonexistent-file.txt', 'test-output.txt');
        }


        /**
         * Tests handling of invalid files for decryption.
         *
         * @return void
         */
        public function testInvalidFileForDecryption(): void
        {
            $this->expectException(EncryptionException::class);
            $this->encryption->decryptFile('nonexistent-encrypted-file.txt', 'test-output.txt');
        }
    }
}