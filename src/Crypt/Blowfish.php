<?php

/**
 * Pure-PHP implementation of Blowfish.
 *
 * PHP version 8.1+
 *
 * Useful resources are as follows:
 *
 *  - {@link http://en.wikipedia.org/wiki/Blowfish_(cipher) Wikipedia description of Blowfish}
 *
 * Here's a short example of how to use this library:
 * <code>
 * <?php
 *    include 'vendor/autoload.php';
 *
 *    $blowfish = new \phpseclib3\Crypt\Blowfish('ctr');
 *
 *    $blowfish->setKey('12345678901234567890123456789012');
 *
 *    $plaintext = str_repeat('a', 10 * 1024);
 *
 *    echo $blowfish->decrypt($blowfish->encrypt($plaintext));
 * ?>
 * </code>
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @author    Hans-Juergen Petrich <petrich@tronic-media.com>
 * @copyright 2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib3\Crypt;

use phpseclib3\Crypt\Common\BlockCipher;
use phpseclib3\Exception\{
    BadDecryptionException,
    BadModeException,
    InconsistentSetupException,
    InsufficientSetupException,
    UnsupportedAlgorithmException
};
use phpseclib4\Crypt\Blowfish as BlowfishNew;
use phpseclib4\Exception\{
    BadConfigurationException,
    BadDecryptionException as BadDecryptionExceptionNew,
    BadMethodCallException,
    InvalidArgumentException,
    InvalidModeException,
    InvalidStateException,
    LengthException,
    ResourceLimitException,
    UnsupportedAlgorithmException as UnsupportedAlgorithmExceptionNew
};

/**
 * Pure-PHP implementation of Blowfish.
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 * @author  Hans-Juergen Petrich <petrich@tronic-media.com>
 */
class Blowfish extends BlockCipher
{
    private BlowfishNew $cipher;

    /**
     * Default Constructor.
     */
    public function __construct(string $mode)
    {
        try {
            $this->cipher = new BlowfishNew($mode);
        } catch (InvalidModeException | InvalidArgumentException $e) {
            // v4 throws InvalidArgumentException for unknown modes and for stream mode and InvalidModeException
            // for GCM (Blowfish's block size is too small for it). v3 throws BadModeException for unknown modes and
            // GCM but Blowfish's own constructor throws \InvalidArgumentException for stream mode
            if ($e instanceof InvalidArgumentException && strtolower($mode) === 'stream') {
                throw new \InvalidArgumentException($e->getMessage());
            }
            throw new BadModeException($e->getMessage());
        }
    }

    /**
     * Performs OpenSSH-style bcrypt
     */
    public static function bcrypt_pbkdf(string $pass, string $salt, int $keylen, int $rounds): string
    {
        try {
            return BlowfishNew::bcrypt_pbkdf($pass, $salt, $keylen, $rounds);
        } catch (BadConfigurationException $e) {
            // bcrypt isn't supported on 32-bit versions of PHP
            throw new \RuntimeException($e->getMessage());
        }
    }

    /**
     * Passes calls through to phpseclib4\Crypt\Blowfish, converting phpseclib 4 exceptions to phpseclib 3 exceptions
     *
     * BadMethodCallException and InvalidArgumentException both extend InvalidStateException so they need to be
     * caught before InvalidStateException is
     */
    public function __call(string $name, array $args): mixed
    {
        $arg = $args[array_key_first($args)] ?? null;
        try {
            return $this->cipher->$name(...$args);
        } catch (LengthException $e) {
            // v4 uses LengthException both for unsupported key lengths (v3: \LengthException) and for keys that
            // conflict with an earlier setKeyLength() / setKey() call (v3: InconsistentSetupException). Blowfish
            // accepts keys of any size so any exception setKey() throws is a conflict. setKeyLength() checks the
            // length before the parent class checks for conflicts so if the length is supported then the exception
            // came from the conflict check
            if ($name === 'setKey' || ($name === 'setKeyLength' && is_int($arg) && $arg >= 32 && $arg <= 448)) {
                throw new InconsistentSetupException($e->getMessage());
            }
            throw new \LengthException($e->getMessage());
        } catch (BadDecryptionExceptionNew $e) {
            // v4 uses BadDecryptionException when the ciphertext isn't a multiple of the block size; v3 used
            // \LengthException for that. v4 only does that check in paddable modes (ECB and CBC). bad padding and
            // tag mismatches are BadDecryptionExceptions in both versions
            if (
                $name === 'decrypt' && is_string($arg) &&
                in_array($this->cipher->getMode(), ['ecb', 'cbc'], true) &&
                strlen($arg) % 8
            ) {
                throw new \LengthException($e->getMessage());
            }
            throw new BadDecryptionException($e->getMessage());
        } catch (BadMethodCallException $e) {
            throw new \BadMethodCallException($e->getMessage());
        } catch (InvalidArgumentException | ResourceLimitException $e) {
            // both are only thrown by setPassword() (missing bcrypt salt / iteration count too high)
            throw new \RuntimeException($e->getMessage());
        } catch (InvalidStateException $e) {
            // missing key / IV / nonce / authentication tag
            throw new InsufficientSetupException($e->getMessage());
        } catch (UnsupportedAlgorithmExceptionNew $e) {
            throw new UnsupportedAlgorithmException($e->getMessage());
        }
    }
}
