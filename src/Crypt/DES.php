<?php

/**
 * Pure-PHP implementation of DES.
 *
 * Uses mcrypt, if available, and an internal implementation, otherwise.
 *
 * PHP version 8.1+
 *
 * Useful resources are as follows:
 *
 *  - {@link http://en.wikipedia.org/wiki/DES_supplementary_material Wikipedia: DES supplementary material}
 *  - {@link http://www.itl.nist.gov/fipspubs/fip46-2.htm FIPS 46-2 - (DES), Data Encryption Standard}
 *  - {@link http://www.cs.eku.edu/faculty/styer/460/Encrypt/JS-DES.html JavaScript DES Example}
 *
 * Here's a short example of how to use this library:
 * <code>
 * <?php
 *    include 'vendor/autoload.php';
 *
 *    $des = new \phpseclib3\Crypt\DES('ctr');
 *
 *    $des->setKey('abcdefgh');
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
use phpseclib4\Crypt\DES as DESNew;
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
 * Pure-PHP implementation of DES.
 *
 * @author Jim Wigginton <terrafrost@php.net>
 */
class DES extends BlockCipher
{
    /**
     * Contains $keys[self::ENCRYPT]
     */
    public const ENCRYPT = 0;

    /**
     * Contains $keys[self::DECRYPT]
     */
    public const DECRYPT = 1;

    private DESNew $cipher;

    /**
     * Default Constructor.
     */
    public function __construct(string $mode)
    {
        try {
            $this->cipher = new DESNew($mode);
        } catch (InvalidModeException | InvalidArgumentException $e) {
            // v4 throws InvalidArgumentException for unknown modes and for stream mode and InvalidModeException
            // for GCM (DES's block size is too small for it). v3 throws BadModeException for all of them
            throw new BadModeException($e->getMessage());
        }
    }

    /**
     * Passes calls through to phpseclib4\Crypt\DES, converting phpseclib 4 exceptions to phpseclib 3 exceptions
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
            // conflict with an earlier setKeyLength() / setKey() call (v3: InconsistentSetupException). DES checks
            // the size of the key before the parent class checks for conflicts so if the size is supported then the
            // exception came from the conflict check. setKeyLength() doesn't check the length for DES so any
            // exception it throws is a conflict
            if (($name === 'setKey' && is_string($arg) && strlen($arg) == 8) || $name === 'setKeyLength') {
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
    }
}
