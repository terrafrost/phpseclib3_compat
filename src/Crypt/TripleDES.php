<?php

/**
 * Pure-PHP implementation of Triple DES.
 *
 * Uses mcrypt, if available, and an internal implementation, otherwise.  Operates in the EDE3 mode (encrypt-decrypt-encrypt).
 *
 * PHP version 8.1+
 *
 * Here's a short example of how to use this library:
 * <code>
 * <?php
 *    include 'vendor/autoload.php';
 *
 *    $des = new \phpseclib3\Crypt\TripleDES('ctr');
 *
 *    $des->setKey('abcdefghijklmnopqrstuvwx');
 *
 *    $plaintext = str_repeat('a', 1024);
 *
 *    echo $des->decrypt($des->encrypt($plaintext));
 * ?>
 * </code>
 *
 * @author    Jim Wigginton <terrafrost@php.net>
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
use phpseclib4\Crypt\TripleDES as TripleDESNew;
use phpseclib4\Exception\{
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
 * Pure-PHP implementation of Triple DES.
 *
 * @author Jim Wigginton <terrafrost@php.net>
 */
class TripleDES extends BlockCipher
{
    /**
     * Encrypt / decrypt using inner chaining
     *
     * Inner chaining is used by SSH-1 and is generally considered to be less secure then outer chaining (self::MODE_CBC3).
     */
    public const MODE_3CBC = -2;

    /**
     * Encrypt / decrypt using outer chaining
     *
     * Outer chaining is used by SSH-2 and when the mode is set to \phpseclib3\Crypt\Common\BlockCipher::MODE_CBC.
     */
    public const MODE_CBC3 = self::MODE_CBC;

    private TripleDESNew $cipher;

    /**
     * Is the 3CBC (inner chaining) mode being used?
     *
     * phpseclib4\Crypt\TripleDES doesn't expose this - getMode() returns 'cbc' for 3CBC
     */
    private bool $mode3cbc = false;

    /**
     * Has a key been set?
     *
     * Only tracked to work around phpseclib4\Crypt\TripleDES throwing a TypeError in 3CBC mode when no key has been
     * set (it calls strlen() on the null key)
     */
    private bool $keySet = false;

    /**
     * Default Constructor.
     */
    public function __construct(string $mode)
    {
        try {
            $this->cipher = new TripleDESNew($mode);
        } catch (InvalidModeException | InvalidArgumentException $e) {
            // v4 throws InvalidArgumentException for unknown modes and for stream mode and InvalidModeException
            // for GCM (DES's block size is too small for it). v3 throws BadModeException for all of them
            throw new BadModeException($e->getMessage());
        }
        $this->mode3cbc = strtolower($mode) === '3cbc';
    }

    /**
     * Passes calls through to phpseclib4\Crypt\TripleDES, converting phpseclib 4 exceptions to phpseclib 3 exceptions
     *
     * BadMethodCallException and InvalidArgumentException both extend InvalidStateException so they need to be
     * caught before InvalidStateException is
     */
    public function __call(string $name, array $args): mixed
    {
        if ($this->mode3cbc && !$this->keySet && in_array($name, ['encrypt', 'decrypt'], true)) {
            throw new InsufficientSetupException('No key has been defined - call setKey() first');
        }

        $arg = $args[array_key_first($args)] ?? null;
        try {
            $result = $this->cipher->$name(...$args);
        } catch (LengthException $e) {
            // v4 uses LengthException both for unsupported key sizes (v3: \LengthException) and for keys that
            // conflict with an earlier setKeyLength() / setKey() call. TripleDES::setKey() does its own conflict
            // check, which throws a \LengthException in v3, but setKeyLength() conflicts are caught by the parent
            // class, which throws InconsistentSetupException in v3. setKeyLength() checks the length before the
            // parent class checks for conflicts so if the length is supported then the exception came from the
            // conflict check
            if ($name === 'setKeyLength' && in_array($arg, [128, 192], true)) {
                throw new InconsistentSetupException($e->getMessage());
            }
            throw new \LengthException($e->getMessage());
        } catch (BadDecryptionExceptionNew $e) {
            // v4 uses BadDecryptionException when the ciphertext isn't a multiple of the block size; v3 used
            // \LengthException for that, except in 3CBC mode, where both use BadDecryptionException. v4 only does
            // that check in paddable modes (ECB and CBC). bad padding and tag mismatches are BadDecryptionExceptions
            // in both versions
            if (
                $name === 'decrypt' && is_string($arg) && !$this->mode3cbc &&
                in_array($this->cipher->getMode(), ['ecb', 'cbc'], true) &&
                strlen($arg) % $this->cipher->getBlockLengthInBytes()
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

        if ($name === 'setKey' || $name === 'setPassword') {
            $this->keySet = true;
        }

        return $result;
    }
}
