<?php

declare(strict_types=1);

namespace Temant\EncryptionManager\Contract;

/**
 * Abstraction for draining OpenSSL error messages.
 *
 * Exists purely to make OpenSSL error handling testable and deterministic.
 */
interface OpenSslErrorProviderInterface
{
    /**
     * Fetch the next OpenSSL error message.
     *
     * @return string|false Error string, or false when no more errors exist.
     */
    public function nextError(): string|false;
} 