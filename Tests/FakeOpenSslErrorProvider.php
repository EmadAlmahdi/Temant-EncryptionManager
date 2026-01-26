<?php

declare(strict_types=1);

namespace Temant\EncryptionManager\Tests;

use Temant\EncryptionManager\Contract\OpenSslErrorProviderInterface;

/**
 * Deterministic test double for OpenSSL error queue.
 */
final class FakeOpenSslErrorProvider implements OpenSslErrorProviderInterface
{
    /**
     * @var list<string>
     */
    private array $errors;

    /**
     * @param list<string> $errors Errors to return sequentially.
     */
    public function __construct(array $errors)
    {
        $this->errors = $errors;
    }

    /**
     * {@inheritDoc}
     */
    public function nextError(): string|false
    {
        if ($this->errors === []) {
            return false;
        }

        return array_shift($this->errors);
    }
}