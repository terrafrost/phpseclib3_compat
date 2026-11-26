<?php

/**
 * Pure-PHP implementation of RC4.
 *
 * PHP version 8.1+
 *
 * Useful resources are as follows:
 *
 *  - {@link http://www.mozilla.org/projects/security/pki/nss/draft-kaukonen-cipher-arcfour-03.txt ARCFOUR Algorithm}
 *  - {@link http://en.wikipedia.org/wiki/RC4 - Wikipedia: RC4}
 *
 * RC4 is also known as ARCFOUR or ARC4.  The reason is elaborated upon at Wikipedia.  This class is named RC4 and not
 * ARCFOUR or ARC4 because RC4 is how it is referred to in the SSH1 specification.
 *
 * Here's a short example of how to use this library:
 * <code>
 * <?php
 *    include 'vendor/autoload.php';
 *
 *    $rc4 = new \phpseclib3\Crypt\RC4();
 *
 *    $rc4->setKey('abcdefgh');
 *
 *    $plaintext = str_repeat('a', 10 * 1024);
 *
 *    echo $rc4->decrypt($rc4->encrypt($plaintext));
 * ?>
 * </code>
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
use phpseclib4\Crypt\RC4 as RC4New;
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
 * Pure-PHP implementation of RC4.
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class RC4 extends StreamCipher
{
    /**
     * @see \phpseclib3\Crypt\RC4::_crypt()
     */
    public const ENCRYPT = 0;

    /**
     * @see \phpseclib3\Crypt\RC4::_crypt()
     */
    public const DECRYPT = 1;

    private RC4New $cipher;

    /**
     * Default Constructor.
     */
    public function __construct()
    {
        $this->cipher = new RC4New();
    }

    /**
     * Passes calls through to phpseclib4\Crypt\RC4, converting phpseclib 4 exceptions to phpseclib 3 exceptions
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
            // conflict with an earlier setKeyLength() / setKey() call (v3: InconsistentSetupException). RC4 checks
            // the size of the key before the parent class checks for conflicts so if the size is supported then the
            // exception came from the conflict check
            if (
                ($name === 'setKey' && is_string($arg) && strlen($arg) >= 1 && strlen($arg) <= 256) ||
                ($name === 'setKeyLength' && is_int($arg) && $arg >= 8 && $arg <= 2048)
            ) {
                throw new InconsistentSetupException($e->getMessage());
            }
            throw new \LengthException($e->getMessage());
        } catch (BadDecryptionExceptionNew $e) {
            throw new BadDecryptionException($e->getMessage());
        } catch (BadMethodCallException $e) {
            throw new \BadMethodCallException($e->getMessage());
        } catch (InvalidArgumentException | ResourceLimitException $e) {
            // both are only thrown by setPassword() (missing bcrypt salt / iteration count too high)
            throw new \RuntimeException($e->getMessage());
        } catch (InvalidStateException $e) {
            // missing key
            throw new InsufficientSetupException($e->getMessage());
        } catch (UnsupportedAlgorithmExceptionNew $e) {
            throw new UnsupportedAlgorithmException($e->getMessage());
        }
    }
}
