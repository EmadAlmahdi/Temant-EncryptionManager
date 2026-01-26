<?php

declare(strict_types=1);

namespace Temant\EncryptionManager\Crypto;

use Temant\EncryptionManager\Contract\OpenSslErrorProviderInterface;

/**
 * Native OpenSSL error provider using PHP's openssl_error_string().
 */
final class NativeOpenSslErrorProvider implements OpenSslErrorProviderInterface
{
    /**
     * {@inheritDoc}
     */
    public function nextError(): string|false
    {
        return openssl_error_string();
    }
}