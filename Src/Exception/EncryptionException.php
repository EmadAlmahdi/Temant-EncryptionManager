<?php declare(strict_types=1);

namespace Temant\EncryptionManager\Exception {

    use Exception;
    use Throwable;

    /**
     * Exception class for handling encryption-related errors.
     */
    class EncryptionException extends Exception implements Throwable
    {
        /**
         * Constructor for EncryptionException.
         *
         * @param string $message The error message for this exception.
         * @param int $code The error code for this exception
         */
        public function __construct(string $message = "", int $code = 0)
        {
            parent::__construct($message, $code);
        }
    }
}