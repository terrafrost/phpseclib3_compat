<?php

/**
 * Pure-PHP implementation of EC.
 *
 * Here's an example of how to create signatures and verify signatures with this library:
 * <code>
 * <?php
 * include 'vendor/autoload.php';
 *
 * $private = \phpseclib3\Crypt\EC::createKey('secp256k1');
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
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      https://phpseclib.com/
 */

declare(strict_types=1);

namespace phpseclib3\Crypt;

use phpseclib3\Crypt\Common\AsymmetricKey;
use phpseclib3\Crypt\EC\{Parameters, PrivateKey, PublicKey};
use phpseclib3\Exception\{
    BadConfigurationException,
    NoKeyLoadedException,
    UnsupportedAlgorithmException,
    UnsupportedCurveException,
    UnsupportedOperationException
};
use phpseclib4\Crypt\{Hash as Hash2, EC as EC2};
use phpseclib4\Exception\{
    BadConfigurationException as BadConfigurationExceptionNew,
    BadMethodCallException,
    LengthException,
    NoKeyLoadedException as NoKeyLoadedExceptionNew,
    UnsupportedCurveException as UnsupportedCurveExceptionNew
};

/**
 * Pure-PHP implementation of EC.
 *
 * @author Jim Wigginton <terrafrost@php.net>
 * @method static PrivateKey createKey(string $curve)
 * @method string|array getCurve()
 * @method int getLength()
 * @method string getEncodedCoordinates()
 * @method static PublicKey|string convertPointToPublicKey(string $curveName, string $secret, bool $toPublicKey = true)
 * @method Parameters getParameters(string $type = 'PKCS1')
 * @method EC withSignatureFormat(string $format)
 * @method string getSignatureFormat()
 * @method EC withContext(?string $context = null)
 * @method string getContext()
 */
abstract class EC extends AsymmetricKey
{
    protected EC2 $key;

    public function __call(string $name, array $args): mixed
    {
        try {
            $result = $this->key->$name(...$args);
        } catch (BadMethodCallException $e) {
            throw match ($name) {
                'withHash' => new UnsupportedAlgorithmException($e->getMessage()),
                'withContext' => new UnsupportedCurveException($e->getMessage()),
                'withSignatureFormat' => new UnsupportedOperationException($e->getMessage()),
                default => $e,
            };
        } catch (LengthException $e) {
            throw new \LengthException($e->getMessage());
        }
        $result = $this->key->$name(...$args);
        if ($result instanceof EC2) {
            $temp = match ($result::class) {
                // needed for EC::getParameters()
                EC2\Parameters::class => new EC\Parameters(),
                // needed for withHash() and the like
                EC2\PrivateKey::class => new EC\PrivateKey(),
                EC2\PublicKey::class => new EC\PublicKey()
            };
            $temp->key = $result;
            return $temp;
        }
        // this bit is needed for PublicKey::getHash(), PrivateKey::getHash(), etc.
        if ($result instanceof Hash2) {
            return new Hash($result->getHash());
        }
        return $result;
    }

    public static function __callStatic(string $name, array $args): mixed
    {
        if (substr($name, 0, 4) == 'load' && ($args[1] ?? false) === false) {
            $args[1] = null;
        }
        try {
            $result = EC2::$name(...$args);
        } catch (NoKeyLoadedExceptionNew $e) {
            throw new NoKeyLoadedException($e->getMessage());
        } catch (BadMethodCallException $e) {
            throw new \RuntimeException($e->getMessage());
        } catch (UnsupportedCurveExceptionNew $e) {
            throw new UnsupportedCurveException($e->getMessage());
        } catch (BadConfigurationExceptionNew $e) {
            throw new BadConfigurationException($e->getMessage());
        }
        // this bit is needed for EC::createKey(), EC::loadFormat(), etc.
        if ($result instanceof EC2) {
            $temp = match ($result::class) {
                EC2\PrivateKey::class => new EC\PrivateKey(),
                EC2\PublicKey::class => new EC\PublicKey()
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
