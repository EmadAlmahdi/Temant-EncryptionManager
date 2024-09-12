<?php declare(strict_types=1);

namespace Temant\EncryptionManager {

    use Temant\EncryptionManager\Exception\EncryptionException;

    /**
     * Class EncryptionManager
     * Handles encryption and decryption of data using a specified cipher and key.
     */
    class EncryptionManager
    {
        private EncryptionTypeEnum $cipher;
        private string $key;
        private int $ivLength;

        /**
         * Encryption constructor.
         * @param string $key The key used for encryption/decryption.
         * @param EncryptionTypeEnum $cipher The cipher type to use.
         */
        public function __construct(string $key, EncryptionTypeEnum $cipher = EncryptionTypeEnum::BYTES_256)
        {
            $this->cipher = $cipher;
            $this->key = KeyGenerator::generateKey($key);
            $this->ivLength = (int) openssl_cipher_iv_length($this->cipher->value);
        }

        /**
         * Updates the encryption key.
         * @param string $newKey The new key to be used.
         */
        public function updateKey(string $newKey): void
        {
            $this->key = KeyGenerator::generateKey($newKey);
        }

        /**
         * Gets the current key.
         * @return string The current encryption key.
         */
        public function getKey(): string
        {
            return $this->key;
        }

        /**
         * Gets the current IV length.
         * @return int The length of the initialization vector.
         */
        public function getIvLength(): int
        {
            return $this->ivLength;
        }

        /**
         * Encrypts the given data.
         * @param string $data The data to encrypt.
         * @param string|null $password Optional password for key derivation.
         * @return string The encrypted and base64 encoded data.
         * @throws EncryptionException If encryption fails.
         */
        public function encryptString(string $data, ?string $password = null): string
        {
            return $password !== null
                ? $this->encryptWithPassword($data, $password)
                : $this->encryptWithoutPassword($data);
        }

        /**
         * Decrypts the given data.
         * @param string $data The base64 encoded encrypted data.
         * @param string|null $password Optional password for key derivation.
         * @return string The decrypted data.
         * @throws EncryptionException If decryption fails.
         */
        public function decryptString(string $data, ?string $password = null): string
        {
            $decodedData = $this->decode($data);

            return $password !== null
                ? $this->decryptWithPassword($decodedData, $password)
                : $this->decryptWithoutPassword($decodedData);
        }

        /**
         * Encrypts a file and saves it to the specified output file.
         * @param string $inputFile Path to the input file.
         * @param string $outputFile Path to the output file.
         * @param string|null $password Optional password for key derivation.
         * @throws EncryptionException If file operations fail.
         */
        public function encryptFile(string $inputFile, string $outputFile, ?string $password = null): void
        {
            $this->validateFile($inputFile);
            $data = (string) file_get_contents($inputFile);
            $encryptedData = $this->encryptString($data, $password);
            file_put_contents($outputFile, $encryptedData);
        }

        /**
         * Decrypts a file and saves it to the specified output file.
         * @param string $inputFile Path to the input file.
         * @param string $outputFile Path to the output file.
         * @param string|null $password Optional password for key derivation.
         * @throws EncryptionException If file operations fail.
         */
        public function decryptFile(string $inputFile, string $outputFile, ?string $password = null): void
        {
            $this->validateFile($inputFile);
            $data = (string) file_get_contents($inputFile);
            $decryptedData = $this->decryptString($data, $password);
            file_put_contents($outputFile, $decryptedData);
        }

        /**
         * Encrypts data using a password.
         * @param string $data The data to encrypt.
         * @param string $password The password for key derivation.
         * @return string The encrypted and base64 encoded data.
         */
        private function encryptWithPassword(string $data, string $password): string
        {
            $salt = KeyGenerator::generateIv(8);
            $keyIv = KeyGenerator::generateKeyIv($password, $salt, $this->ivLength);
            $encrypted = (string) openssl_encrypt($data, $this->cipher->value, $keyIv['key'], OPENSSL_RAW_DATA, $keyIv['iv']);

            return $this->encode($salt . $keyIv['iv'] . $encrypted);
        }

        /**
         * Encrypts data without using a password.
         * @param string $data The data to encrypt.
         * @return string The encrypted and base64 encoded data.
         */
        private function encryptWithoutPassword(string $data): string
        {
            $iv = KeyGenerator::generateIv($this->ivLength);
            $encrypted = (string) openssl_encrypt($data, $this->cipher->value, $this->key, OPENSSL_RAW_DATA, $iv);

            return $this->encode("$iv$encrypted");
        }

        /**
         * Decrypts data using a password.
         * @param string $data The base64 encoded encrypted data.
         * @param string $password The password for key derivation.
         * @return string The decrypted data.
         * @throws EncryptionException If decryption fails.
         */
        private function decryptWithPassword(string $data, string $password): string
        {
            $salt = substr($data, 0, 8);
            $iv = substr($data, 8, $this->ivLength);
            $encrypted = substr($data, 8 + $this->ivLength);
            $keyIv = KeyGenerator::generateKeyIv($password, $salt, $this->ivLength);
            $decrypted = openssl_decrypt($encrypted, $this->cipher->value, $keyIv['key'], OPENSSL_RAW_DATA, $iv);

            if ($decrypted === false) {
                throw new EncryptionException("Decryption failed");
            }

            return $decrypted;
        }

        /**
         * Decrypts data without using a password.
         * @param string $data The base64 encoded encrypted data.
         * @return string The decrypted data.
         * @throws EncryptionException If decryption fails.
         */
        private function decryptWithoutPassword(string $data): string
        {
            $iv = substr($data, 0, $this->ivLength);
            $encrypted = substr($data, $this->ivLength);
            $decrypted = openssl_decrypt($encrypted, $this->cipher->value, $this->key, OPENSSL_RAW_DATA, $iv);

            if ($decrypted === false) {
                throw new EncryptionException("Decryption failed");
            }

            return $decrypted;
        }

        /**
         * Encodes data to base64.
         * @param string $data The data to encode.
         * @return string The base64 encoded data.
         */
        private function encode(string $data): string
        {
            return base64_encode($data);
        }

        /**
         * Decodes base64 data.
         * @param string $data The base64 encoded data.
         * @return string The decoded data.
         */
        private function decode(string $data): string
        {
            return base64_decode($data, true) ?: '';
        }

        /**
         * Validates if a file exists.
         * @param string $filePath Path to the file.
         * @throws EncryptionException If the file does not exist.
         */
        private function validateFile(string $filePath): void
        {
            if (!file_exists($filePath)) {
                throw new EncryptionException("File does not exist: $filePath");
            }
        }
    }
}