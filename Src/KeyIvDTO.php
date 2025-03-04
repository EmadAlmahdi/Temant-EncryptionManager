<?php declare(strict_types=1);

namespace Temant\EncryptionManager;

/**
 * Data Transfer Object for encryption key and IV.
 */
class KeyIvDTO
{
    public function __construct(
        public readonly string $key,
        public readonly string $iv
    ) {
    }
}
