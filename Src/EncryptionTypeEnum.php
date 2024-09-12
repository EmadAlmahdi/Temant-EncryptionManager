<?php declare(strict_types=1);

namespace Temant\EncryptionManager {
    /**
     * Enum representing the types of encryption ciphers supported.
     */
    enum EncryptionTypeEnum: string
    {
        /**
         * AES-128-CBC encryption cipher.
         * 
         * AES (Advanced Encryption Standard) with a 128-bit key in CBC (Cipher Block Chaining) mode.
         * Suitable for use cases where a balance between security and performance is needed.
         */
        case BYTES_128 = 'AES-128-CBC';

        /**
         * AES-256-CBC encryption cipher.
         * 
         * AES (Advanced Encryption Standard) with a 256-bit key in CBC (Cipher Block Chaining) mode.
         * Provides a higher level of security compared to AES-128, at the cost of slightly reduced performance.
         */
        case BYTES_256 = 'AES-256-CBC';
    }
}