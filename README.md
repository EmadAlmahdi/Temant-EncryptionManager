# Temant Encrypter

Temant Encrypter is a simple and secure encryption library for PHP. It provides an easy-to-use API for encrypting and decrypting strings and files using AES-128-CBC and AES-256-CBC encryption algorithms.

## Installation

You can install the library using Composer:

```bash
composer require temant/encryption-manager
```

## Usage

### Encryption

To encrypt a string:

```php
use Temant\EncryptionManager\EncryptionManager;
use Temant\EncryptionManager\EncryptionTypeEnum;

// Initialize the Encryption class with a key
$encryption = new EncryptionManager('your-encryption-key', EncryptionTypeEnum::BYTES_256);

// Encrypt a string
$plainText = 'Hello, World!';
$encrypted = $encryption->encryptString($plainText);

// Decrypt the string
$decrypted = $encryption->decryptString($encrypted);

echo "Encrypted: $encrypted\n";
echo "Decrypted: $decrypted\n";
```

### Encryption with Password

To encrypt a string with a password:

```php
$plainText = 'Sensitive Data';
$password = 'your-secure-password';

$encrypted = $encryption->encryptString($plainText, $password);
$decrypted = $encryption->decryptString($encrypted, $password);

echo "Encrypted: $encrypted\n";
echo "Decrypted: $decrypted\n";
```

### File Encryption

To encrypt and decrypt files:

```php
// Encrypt a file
$inputFile = 'path/to/input/file.txt';
$encryptedFile = 'path/to/encrypted/file.txt';
$password = 'file-password';

$encryption->encryptFile($inputFile, $encryptedFile, $password);

// Decrypt the file
$decryptedFile = 'path/to/decrypted/file.txt';
$encryption->decryptFile($encryptedFile, $decryptedFile, $password);

$decryptedContent = file_get_contents($decryptedFile);
echo "Decrypted file content: $decryptedContent\n";
```

## Running Tests

To run the tests, use the following command:

```bash
vendor/bin/phpunit
```

## License

This project is licensed under the BSD 3-Clause License License.