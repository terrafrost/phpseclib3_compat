<?php

/**
 * Pure-PHP PKCS#1 (v2.1) compliant implementation of RSA.
 *
 * PHP version 8.1+
 *
 * Here's an example of how to encrypt and decrypt text with this library:
 * <code>
 * <?php
 * include 'vendor/autoload.php';
 *
 * $private = Crypt\RSA::createKey();
 * $public = $private->getPublicKey();
 *
 * $plaintext = 'terrafrost';
 *
 * $ciphertext = $public->encrypt($plaintext);
 *
 * echo $private->decrypt($ciphertext);
 * ?>
 * </code>
 *
 * Here's an example of how to create signatures and verify signatures with this library:
 * <code>
 * <?php
 * include 'vendor/autoload.php';
 *
 * $private = Crypt\RSA::createKey();
 * $public = $private->getPublicKey();
 *
 * $plaintext = 'terrafrost';
 *
 * $signature = $private->sign($plaintext);
 *
 * echo $public->verify($plaintext, $signature) ? 'verified' : 'unverified';
 * ?>
 * </code>
 *
 * One thing to consider when using this: so phpseclib uses PSS mode by default.
 * Technically, id-RSASSA-PSS has a different key format than rsaEncryption. So
 * should phpseclib save to the id-RSASSA-PSS format by default or the
 * rsaEncryption format? For stand-alone keys I figure rsaEncryption is better
 * because SSH doesn't use PSS and idk how many SSH servers would be able to
 * decode an id-RSASSA-PSS key. For X.509 certificates the id-RSASSA-PSS
 * format is used by default (unless you change it up to use PKCS1 instead)
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib3\Crypt;

use phpseclib3\Crypt\Common\AsymmetricKey;
use phpseclib3\Crypt\RSA\{PrivateKey, PublicKey};
use phpseclib3\Exception\{
    BadConfigurationException,
    InconsistentSetupException,
    NoKeyLoadedException,
    UnsupportedAlgorithmException,
    UnsupportedFormatException
};
use phpseclib4\Crypt\{Hash as Hash2, RSA as RSA2};
use phpseclib4\Exception\{
    BadConfigurationException as BadConfigurationExceptionNew,
    BadMethodCallException,
    InvalidArgumentException,
    InvalidStateException,
    KeyConstraintException,
    NoKeyLoadedException as NoKeyLoadedExceptionNew,
    UnsupportedAlgorithmException as UnsupportedAlgorithmExceptionNew
};
use phpseclib4\Math\BigInteger as NewBigInteger;

/**
 * Pure-PHP PKCS#1 compliant implementation of RSA.
 *
 * We can't extend RSA2 because some of those methods return \phpseclib4\Crypt\RSA\{PrivateKey, Publickey}.
 * like the namespace that's returned needs to be phpseclib3 - not phpseclib4. hence our using composition
 * vs inheritance
 *
 * @author Jim Wigginton <terrafrost@php.net>
 * @method static PrivateKey createKey(int $bits)
 * @method Hash getMGFHash()
 * @method RSA withMGFHash(string $hash)
 * @method ?int getSaltLength()
 * @method RSA withSaltLength()
 * @method string getLabel()
 * @method RSA withLabel(string $label)
 * @method int getPadding()
 * @method RSA withPadding(int $padding)
 * @method static void enableBlinding()
 * @method static void disableBlinding()
 */
abstract class RSA extends AsymmetricKey
{
    /**
     * Use {@link http://en.wikipedia.org/wiki/Optimal_Asymmetric_Encryption_Padding Optimal Asymmetric Encryption Padding}
     * (OAEP) for encryption / decryption.
     *
     * Uses sha256 by default
     *
     * @see self::setHash()
     * @see self::setMGFHash()
     * @see self::encrypt()
     * @see self::decrypt()
     */
    const ENCRYPTION_OAEP = 1;

    /**
     * Use PKCS#1 padding.
     *
     * Although self::PADDING_OAEP / self::PADDING_PSS  offers more security, including PKCS#1 padding is necessary for purposes of backwards
     * compatibility with protocols (like SSH-1) written before OAEP's introduction.
     *
     * @see self::encrypt()
     * @see self::decrypt()
     */
    const ENCRYPTION_PKCS1 = 2;

    /**
     * Do not use any padding
     *
     * Although this method is not recommended it can none-the-less sometimes be useful if you're trying to decrypt some legacy
     * stuff, if you're trying to diagnose why an encrypted message isn't decrypting, etc.
     *
     * @see self::encrypt()
     * @see self::decrypt()
     */
    const ENCRYPTION_NONE = 4;

    /**
     * Use the Probabilistic Signature Scheme for signing
     *
     * Uses sha256 and 0 as the salt length
     *
     * @see self::setSaltLength()
     * @see self::setMGFHash()
     * @see self::setHash()
     * @see self::sign()
     * @see self::verify()
     * @see self::setHash()
     */
    const SIGNATURE_PSS = 16;

    /**
     * Use a relaxed version of PKCS#1 padding for signature verification
     *
     * @see self::sign()
     * @see self::verify()
     * @see self::setHash()
     */
    const SIGNATURE_RELAXED_PKCS1 = 32;

    /**
     * Use PKCS#1 padding for signature verification
     *
     * @see self::sign()
     * @see self::verify()
     * @see self::setHash()
     */
    const SIGNATURE_PKCS1 = 64;

    protected RSA2 $key;

    protected int $origPadding = self::ENCRYPTION_OAEP | self::SIGNATURE_PSS;

    public function __call(string $name, array $args): mixed
    {
        if ($name === 'toString' && $args[0] === 'Raw') {
            $name = 'toArray';
            $args = [];
        }
        $newPadding = $this->origPadding;
        if ($name === 'withPadding') {
            $encryptionMask = self::ENCRYPTION_OAEP | self::ENCRYPTION_PKCS1 | self::ENCRYPTION_NONE;
            $signatureMask = self::SIGNATURE_PSS | self::SIGNATURE_RELAXED_PKCS1 | self::SIGNATURE_PKCS1;
            if ($args[0] & $encryptionMask) {
                $newPadding = ($newPadding & ~$encryptionMask) | ($args[0] & $encryptionMask);
            }
            if ($args[0] & $signatureMask) {
                $newPadding = ($newPadding & ~$signatureMask) | ($args[0] & $signatureMask);
            }
            if ($args[0] & self::SIGNATURE_PKCS1) {
                // v4 removed SIGNATURE_RELAXED_PKCS1 (32) and reassigned SIGNATURE_PKCS1 (previously 64) to 32
                $args[0] = ($args[0] & ~self::SIGNATURE_PKCS1) | RSA2::SIGNATURE_PKCS1;
            }
        }
        if ($name === 'getPadding') {
            return $this->origPadding;
        }

        try {
            $result = $this->key->$name(...$args);
        } catch (UnsupportedAlgorithmExceptionNew $e) {
            throw new UnsupportedAlgorithmException($e->getMessage());
        } catch (InconsistentSetupException $e) {
            throw new InvalidStateException($e->getMessage());
        } catch (BadConfigurationExceptionNew $e) {
            throw new BadConfigurationException($e->getMessage());
        } catch (InvalidArgumentException $e) {
            throw new UnsupportedFormatException($e->getMessage());
        } catch (KeyConstraintException $e) {
            throw new \LengthException($e->getMessage());
        }
        // this bit is needed for RSA::withHash(), PublicKey::asPrivateKey(), etc
        if ($result instanceof RSA2) {
            $temp = match ($result::class) {
                RSA2\PrivateKey::class => new RSA\PrivateKey(),
                RSA2\PublicKey::class => new RSA\PublicKey()
            };
            $temp->key = $result;
            $temp->origPadding = $newPadding;
            return $temp;
        }
        // this bit is needed for PublicKey::getHash(), PrivateKey::getHash(), etc.
        if ($result instanceof Hash2) {
            return $result->getHash();
        }
        return $result;
    }

    public static function __callStatic(string $name, array $args): mixed
    {
        if (substr($name, 0, 4) == 'load' && ($args[1] ?? false) === false) {
            if (is_array($args[0])) {
                $args[0] = array_map(fn ($x) => new NewBigInteger((string) $x), $args[0]);
            }
            $args[1] = null;
        }
        try {
            $result = RSA2::$name(...$args);
        } catch (NoKeyLoadedExceptionNew $e) {
            throw new NoKeyLoadedException($e->getMessage());
        } catch (BadMethodCallException $e) {
            throw new \RuntimeException($e->getMessage());
        } catch (BadConfigurationExceptionNew $e) {
            throw new BadConfigurationException($e->getMessage());
        }
        // this bit is needed for RSA::createKey(), RSA::loadFormat(), etc.
        if ($result instanceof RSA2) {
            $temp = match ($result::class) {
                RSA2\PrivateKey::class => new RSA\PrivateKey(),
                RSA2\PublicKey::class => new RSA\PublicKey()
            };
            $temp->key = $result;
            return $temp;
        }
        return $result;
    }

    public function __toString(): string
    {
        return (string) $this->key;
    }
}
