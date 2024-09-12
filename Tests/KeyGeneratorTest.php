<?php declare(strict_types=1);

namespace Temant\Encrypter\Tests {

    use Temant\EncryptionManager\KeyGenerator;
    use PHPUnit\Framework\TestCase;

    /**
     * Test suite for the KeyGenerator class.
     */
    class KeyGeneratorTest extends TestCase
    {
        /**
         * Tests the generation of a key from a password.
         *
         * @return void
         */
        public function testGenerateKey(): void
        {
            $password = 'test-password';
            $expectedKey = hash('sha256', $password, true);
            $generatedKey = KeyGenerator::generateKey($password);

            $this->assertEquals($expectedKey, $generatedKey, 'The generated key does not match the expected key.');
        }

        /**
         * Tests the generation of a key and IV from a password and salt.
         *
         * @return void
         */
        public function testGenerateKeyIv(): void
        {
            $password = 'test-password';
            $salt = 'test-salt';
            $ivLength = 16; // Example IV length
            $keyIv = KeyGenerator::generateKeyIv($password, $salt, $ivLength);

            $this->assertArrayHasKey('key', $keyIv);
            $this->assertArrayHasKey('iv', $keyIv);
            $this->assertEquals(32, strlen($keyIv['key']), 'The key length should be 32 bytes.');
            $this->assertEquals($ivLength, strlen($keyIv['iv']), 'The IV length does not match the expected length.');
        }

        /**
         * Tests the generation of a random initialization vector (IV).
         *
         * @return void
         */
        public function testGenerateIv(): void
        {
            $ivLength = 16; // Example IV length
            $iv = KeyGenerator::generateIv($ivLength);

            $this->assertEquals($ivLength, strlen($iv), 'The length of the generated IV does not match the expected length.');
            $this->assertIsString($iv, 'The generated IV should be a string.');

            // Test for random bytes
            $iv2 = KeyGenerator::generateIv($ivLength);
            $this->assertNotEquals($iv, $iv2, 'The generated IV should be different each time.');
        }
    }
}