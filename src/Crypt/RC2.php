<?php

/**
 * Pure-PHP implementation of RC2.
 *
 * PHP version 8.1+
 *
 * Useful resources are as follows:
 *
 *  - {@link http://tools.ietf.org/html/rfc2268}
 *
 * Here's a short example of how to use this library:
 * <code>
 * <?php
 *    include 'vendor/autoload.php';
 *
 *    $rc2 = new \phpseclib3\Crypt\RC2('ctr');
 *
 *    $rc2->setKey('abcdefgh');
 *
 *    $plaintext = str_repeat('a', 1024);
 *
 *    echo $rc2->decrypt($rc2->encrypt($plaintext));
 * ?>
 * </code>
 *
 * @author    Patrick Monnerat <pm@datasphere.ch>
 * @copyright 2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib3\Crypt;

use phpseclib3\Crypt\Common\BlockCipher;
use phpseclib3\Exception\{
    BadDecryptionException,
    BadModeException,
    InsufficientSetupException,
    UnsupportedAlgorithmException
};
use phpseclib4\Crypt\RC2 as RC2New;
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
 * Pure-PHP implementation of RC2.
 *
 * @author  Patrick Monnerat <pm@datasphere.ch>
 */
class RC2 extends BlockCipher
{
    private RC2New $cipher;

    /**
     * Default Constructor.
     */
    public function __construct(string $mode)
    {
        try {
            $this->cipher = new RC2New($mode);
        } catch (InvalidModeException | InvalidArgumentException $e) {
            // v4 throws InvalidArgumentException for unknown modes and for stream mode and InvalidModeException
            // for GCM (RC2's block size is too small for it). v3 throws BadModeException for all of them
            throw new BadModeException($e->getMessage());
        }
    }

    /**
     * Passes calls through to phpseclib4\Crypt\RC2, converting phpseclib 4 exceptions to phpseclib 3 exceptions
     *
     * BadMethodCallException and InvalidArgumentException both extend InvalidStateException so they need to be
     * caught before InvalidStateException is
     */
    public function __call(string $name, array $args): mixed
    {
        if ($name === 'setKey') {
            // in v3 the effective key length ($t1) defaults to false and false means "use the default". in v4 it
            // defaults to null and null means "use the default". without strict_types, PHP would convert false to 0,
            // which v4 would reject. v3 rejects an explicitly passed null
            $t1Key = array_key_exists(1, $args) ? 1 : (array_key_exists('t1', $args) ? 't1' : null);
            if (isset($t1Key)) {
                if ($args[$t1Key] === false) {
                    unset($args[$t1Key]);
                } elseif ($args[$t1Key] === null) {
                    throw new \LengthException('Key size of  bits is not supported by this algorithm. Only keys between 1 and 1024 bits, inclusive, are supported');
                }
            }
        }

        $arg = $args[array_key_first($args)] ?? null;
        try {
            return $this->cipher->$name(...$args);
        } catch (LengthException $e) {
            // RC2 doesn't check for conflicts between setKey() and setKeyLength() so, unlike other ciphers, these
            // are always unsupported key / key length / IV sizes
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
