<?php

/**
 * Pure-PHP implementation of Salsa20.
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
use phpseclib4\Crypt\Salsa20 as Salsa20New;
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
 * Pure-PHP implementation of Salsa20.
 *
 * @author Jim Wigginton <terrafrost@php.net>
 */
class Salsa20 extends StreamCipher
{
    /**
     * @see Salsa20::crypt()
     */
    public const ENCRYPT = 0;

    /**
     * @see Salsa20::crypt()
     */
    public const DECRYPT = 1;

    private Salsa20New $cipher;

    /**
     * Default Constructor.
     */
    public function __construct()
    {
        $this->cipher = new Salsa20New();
    }

    /**
     * Passes calls through to phpseclib4\Crypt\Salsa20, converting phpseclib 4 exceptions to phpseclib 3 exceptions
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
            // v4 uses LengthException both for unsupported key sizes (v3: \LengthException) and for keys that
            // conflict with an earlier setKeyLength() / setKey() call (v3: InconsistentSetupException). Salsa20
            // checks the size of the key before the parent class checks for conflicts so if the size is supported
            // then the exception came from the conflict check. setKeyLength() doesn't check the length for Salsa20
            // so any exception it throws is a conflict
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
