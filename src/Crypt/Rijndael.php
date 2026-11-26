<?php

/**
 * Pure-PHP implementation of Rijndael.
 *
 * PHP version 8.1+
 *
 * If {@link self::setBlockLength() setBlockLength()} isn't called, it'll be assumed to be 128 bits.  If
 * {@link self::setKeyLength() setKeyLength()} isn't called, it'll be calculated from
 * {@link self::setKey() setKey()}.  ie. if the key is 128-bits, the key length will be 128-bits.  If it's
 * 136-bits it'll be null-padded to 192-bits and 192 bits will be the key length until
 * {@link self::setKey() setKey()} is called, again, at which point, it'll be recalculated.
 *
 * Here's a short example of how to use this library:
 * <code>
 * <?php
 *    include 'vendor/autoload.php';
 *
 *    $rijndael = new \phpseclib3\Crypt\Rijndael('ctr');
 *
 *    $rijndael->setKey('abcdefghijklmnop');
 *
 *    $plaintext = str_repeat('a', 10 * 1024);
 *
 *    echo $rijndael->decrypt($rijndael->encrypt($plaintext));
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
use phpseclib4\Crypt\Rijndael as RijndaelNew;
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
 * Pure-PHP implementation of Rijndael.
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class Rijndael extends BlockCipher
{
    private RijndaelNew $cipher;

    /**
     * The block length (in bytes) the current IV was set for
     *
     * v4 checks that the IV and the block length match when encrypt() / decrypt() is called. it throws a
     * LengthException when they don't whereas v3 throws an InconsistentSetupException. v4's encrypt() also throws
     * a LengthException when padding is disabled and the plaintext isn't a multiple of the block size, which v3
     * also uses \LengthException for. keeping track of this lets us tell the two apart. setIV() rejects IVs that
     * don't match the block length and setPassword() always sets one that does so the IV can only stop matching
     * if setBlockLength() is called after the IV is set.
     */
    private ?int $ivBlockLength = null;

    /**
     * Default Constructor.
     */
    public function __construct(string $mode)
    {
        try {
            $this->cipher = new RijndaelNew($mode);
        } catch (InvalidModeException | InvalidArgumentException $e) {
            // v4 throws InvalidArgumentException for unknown modes and for stream mode. v3 throws BadModeException
            throw new BadModeException($e->getMessage());
        }
    }

    /**
     * Does the IV no longer match the block length?
     *
     * In GCM mode the IV is derived from the nonce and is always 16 bytes long
     */
    private function ivMismatch(): bool
    {
        $blockLength = $this->cipher->getBlockLengthInBytes();
        if ($this->cipher->getMode() === 'gcm') {
            return $blockLength != 16;
        }
        return isset($this->ivBlockLength) && $this->ivBlockLength != $blockLength;
    }

    /**
     * Passes calls through to phpseclib4\Crypt\Rijndael, converting phpseclib 4 exceptions to phpseclib 3 exceptions
     *
     * BadMethodCallException and InvalidArgumentException both extend InvalidStateException so they need to be
     * caught before InvalidStateException is
     */
    public function __call(string $name, array $args): mixed
    {
        $arg = $args[array_key_first($args)] ?? null;
        try {
            $result = $this->cipher->$name(...$args);
        } catch (LengthException $e) {
            // v4 uses LengthException for unsupported key / block / IV sizes (v3: \LengthException), for keys that
            // conflict with an earlier setKeyLength() / setKey() call (v3: InconsistentSetupException) and for IVs
            // that don't match the block length (v3: InconsistentSetupException). Rijndael checks the size of the
            // key before the parent class checks for conflicts so if the size is supported then the exception came
            // from the conflict check
            switch (true) {
                case $name === 'setKey' && is_string($arg) && in_array(strlen($arg), [16, 20, 24, 28, 32], true):
                case $name === 'setKeyLength' && in_array($arg, [128, 160, 192, 224, 256], true):
                case in_array($name, ['encrypt', 'decrypt'], true) && $this->ivMismatch():
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

        if ($name === 'setIV' || $name === 'setPassword') {
            $this->ivBlockLength = $this->cipher->getBlockLengthInBytes();
        }

        return $result;
    }
}
