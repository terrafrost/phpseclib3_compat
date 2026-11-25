<?php

/**
 * Pure-PHP implementation of Twofish.
 *
 * Uses mcrypt, if available, and an internal implementation, otherwise.
 *
 * PHP version 8.1+
 *
 * Useful resources are as follows:
 *
 *  - {@link http://en.wikipedia.org/wiki/Twofish Wikipedia description of Twofish}
 *
 * Here's a short example of how to use this library:
 * <code>
 * <?php
 *    include 'vendor/autoload.php';
 *
 *    $twofish = new \phpseclib3\Crypt\Twofish('ctr');
 *
 *    $twofish->setKey('12345678901234567890123456789012');
 *
 *    $plaintext = str_repeat('a', 1024);
 *
 *    echo $twofish->decrypt($twofish->encrypt($plaintext));
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
use phpseclib4\Crypt\Twofish as TwofishNew;
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
 * Pure-PHP implementation of Twofish.
 *
 * @author Jim Wigginton <terrafrost@php.net>
 * @author Hans-Juergen Petrich <petrich@tronic-media.com>
 */
class Twofish extends BlockCipher
{
    private TwofishNew $cipher;

    /**
     * Default Constructor.
     */
    public function __construct(string $mode)
    {
        try {
            $this->cipher = new TwofishNew($mode);
        } catch (InvalidModeException | InvalidArgumentException $e) {
            // v4 throws InvalidArgumentException for unknown modes and for stream mode and InvalidModeException
            // for GCM with the wrong block size. v3 throws BadModeException for all of them
            throw new BadModeException($e->getMessage());
        }
    }

    /**
     * Passes calls through to phpseclib4\Crypt\Twofish, converting phpseclib 4 exceptions to phpseclib 3 exceptions
     *
     * BadMethodCallException and InvalidArgumentException both extend InvalidStateException so they need to be
     * caught before InvalidStateException is
     */
    public function __call(string $name, array $args): mixed
    {
        try {
            return $this->cipher->$name(...$args);
        } catch (LengthException $e) {
            // v4 uses LengthException for both unsupported key sizes (v3: \LengthException) and for keys that
            // conflict with an earlier setKeyLength() / setKey() call (v3: InconsistentSetupException). Twofish
            // checks the size before the parent class checks for conflicts so if the size is supported then the
            // exception came from the conflict check
            $arg = $args[array_key_first($args)] ?? null;
            if (
                ($name === 'setKey' && is_string($arg) && in_array(strlen($arg), [16, 24, 32], true)) ||
                ($name === 'setKeyLength' && in_array($arg, [128, 192, 256], true))
            ) {
                throw new InconsistentSetupException($e->getMessage());
            }
            throw new \LengthException($e->getMessage());
        } catch (BadDecryptionExceptionNew $e) {
            // v4 uses BadDecryptionException when the ciphertext isn't a multiple of the block size; v3 used
            // \LengthException for that. v4 only does that check in paddable modes (ECB and CBC). bad padding and
            // tag mismatches are BadDecryptionExceptions in both versions
            $arg = $args[array_key_first($args)] ?? null;
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