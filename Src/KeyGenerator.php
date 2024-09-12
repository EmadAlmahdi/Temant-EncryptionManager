<?php declare(strict_types=1);

namespace Temant\EncryptionManager {
    /**
     * Class KeyGenerator
     * Provides methods for generating encryption keys and initialization vectors.
     */
    final class KeyGenerator
    {
        /**
         * Generates a key from the give
         *
         * @param string $password The password to generate the key from.
         * @return string The generated key.
         */
        public static function generateKey(string $password): string
        {
            return hash('sha256', $password, true);
        }

        /**
         * Generates a key and IV from the given password and salt.
         *
         * @param string $password The password used for key and IV generation.
         * @param string $salt The salt used for key and IV generation.
         * @param int $ivLength The length of the IV.
         * @return string[] An associative array containing 'key' and 'iv'.
         */
        public static function generateKeyIv(string $password, string $salt, int $ivLength): array
        {
            $keyIv = hash_pbkdf2('sha256', $password, $salt, 10000, 64, true);
            return [
                'key' => substr($keyIv, 0, 32),
                'iv' => substr($keyIv, 32, $ivLength),
            ];
        }

        /**
         * Generates a random initialization vector of the given length.
         *
         * @param int $length The length of the IV.
         * @return string The generated IV.
         */
        public static function generateIv(int $length): string
        {
            return openssl_random_pseudo_bytes($length);
        }
    }
}