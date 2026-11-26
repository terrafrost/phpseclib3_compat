<?php

/**
 * Pure-PHP implementation of ChaCha20.
 *
 * PHP version 8.1+
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib3\Crypt;

use phpseclib3\Crypt\Common\StreamCipher;
use phpseclib3\Exception\{
    BadDecryptionException,
    InconsistentSetupException,
    InsufficientSetupException,
    UnsupportedAlgorithmException
};
use phpseclib4\Crypt\ChaCha20 as ChaCha20New;
use phpseclib4\Exception\{
    BadDecryptionException as BadDecryptionExceptionNew,
    BadMethodCallException,
    InvalidArgumentException,
    InvalidStateException,
    LengthException,
    ResourceLimitException,
    UnsupportedAlgorithmException as UnsupportedAlgorithmExceptionNew
};

/**
 * Pure-PHP implementation of ChaCha20.
 *
 * @author Jim Wigginton <terrafrost@php.net>
 */
class ChaCha20 extends StreamCipher
{
    /**
     * In phpseclib 3 ChaCha20 extends Salsa20 and inherits these from it
     *
     * @see Salsa20::crypt()
     */
    public const ENCRYPT = 0;

    /**
     * @see Salsa20::crypt()
     */
    public const DECRYPT = 1;

    private ChaCha20New $cipher;

    /**
     * Default Constructor.
     */
    public function __construct()
    {
        $this->cipher = new ChaCha20New();
    }

    /**
     * Passes calls through to phpseclib4\Crypt\ChaCha20, converting phpseclib 4 exceptions to phpseclib 3 exceptions
     *
     * BadMethodCallException and InvalidArgumentException both extend InvalidStateException so they need to be
     * caught before InvalidStateException is
     */
    public function __call(string $name, array $args): mixed
    {
        $arg = $args[array_key_first($args)] ?? null;

        // v3 checks this explicitly; in v4 it's a type declaration, which, without strict_types, would coerce ints
        // and floats to strings and would throw a TypeError for everything else
        if ($name === 'setNonce' && !is_string($arg)) {
            throw new \UnexpectedValueException('The nonce should be a string');
        }

        try {
            return $this->cipher->$name(...$args);
        } catch (LengthException $e) {
            // v4 uses LengthException both for unsupported key / nonce sizes (v3: \LengthException) and for keys
            // that conflict with an earlier setKeyLength() / setKey() call (v3: InconsistentSetupException).
            // ChaCha20 checks the size of the key before the parent class checks for conflicts so if the size is
            // supported then the exception came from the conflict check. setKeyLength() doesn't check the length
            // for ChaCha20 so any exception it throws is a conflict
            if (($name === 'setKey' && is_string($arg) && in_array(strlen($arg), [16, 32], true)) || $name === 'setKeyLength') {
                throw new InconsistentSetupException($e->getMessage());
            }
            throw new \LengthException($e->getMessage());
        } catch (BadDecryptionExceptionNew $e) {
            // authentication tag mismatch
            throw new BadDecryptionException($e->getMessage());
        } catch (BadMethodCallException $e) {
            throw new \BadMethodCallException($e->getMessage());
        } catch (InvalidArgumentException | ResourceLimitException $e) {
            // both are only thrown by setPassword() (missing bcrypt salt / iteration count too high)
            throw new \RuntimeException($e->getMessage());
        } catch (InvalidStateException $e) {
            // missing key / nonce / authentication tag
            throw new InsufficientSetupException($e->getMessage());
        } catch (UnsupportedAlgorithmExceptionNew $e) {
            throw new UnsupportedAlgorithmException($e->getMessage());
        }
    }
}
