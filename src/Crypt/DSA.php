<?php

/**
 * Pure-PHP FIPS 186-4 compliant implementation of DSA.
 *
 * Here's an example of how to create signatures and verify signatures with this library:
 * <code>
 * <?php
 * include 'vendor/autoload.php';
 *
 * $private = \phpseclib3\Crypt\DSA::createKey();
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
use phpseclib3\Crypt\DSA\{Parameters, PrivateKey, PublicKey};
use phpseclib3\Exception\{
    BadConfigurationException,
    NoKeyLoadedException
};
use phpseclib4\Crypt\{DSA as DSA2, Hash as Hash2};
use phpseclib4\Exception\{
    BadConfigurationException as BadConfigurationExceptionNew,
    BadMethodCallException,
    InvalidArgumentException,
    NoKeyLoadedException as NoKeyLoadedExceptionNew
};

/**
 * Pure-PHP FIPS 186-4 compliant implementation of DSA.
 *
 * @author Jim Wigginton <terrafrost@php.net>
 * @method static Parameters createParameters(int $L = 2048, int $N = 224)
 * @method static PrivateKey createKey(int|Parameters ...$args)
 * @method array getLength()
 * @method Parameters getParameters()
 * @method DSA withSignatureFormat(string $format)
 * @method string getSignatureFormat()
 */
abstract class DSA extends AsymmetricKey
{
    protected DSA2 $key;

    public function __call(string $name, array $args): mixed
    {
        if ($name === 'toString' && $args[0] === 'Raw') {
            $name = 'toArray';
            $args = [];
        }
        $result = $this->key->$name(...$args);
        // this bit is needed for DSA::withHash(), tc
        if ($result instanceof DSA2) {
            $temp = match ($result::class) {
                DSA2\PrivateKey::class => new PrivateKey(),
                DSA2\PublicKey::class => new PublicKey()
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
        foreach ($args as &$arg) {
            if ($arg instanceof DSA\Parameters) {
                $arg = $arg->key;
            }
        }
        try {
            $result = DSA2::$name(...$args);
        } catch (NoKeyLoadedExceptionNew $e) {
            throw new NoKeyLoadedException($e->getMessage());
        } catch (BadMethodCallException $e) {
            throw new \RuntimeException($e->getMessage());
        } catch (InvalidArgumentException $e) {
            throw new \InvalidArgumentException($e->getMessage());
        } catch (BadConfigurationExceptionNew $e) {
            throw new BadConfigurationException($e->getMessage());
        }
        // this bit is needed for DSA::createKey(), DSA::loadFormat(), etc.
        if ($result instanceof DSA2) {
            $temp = match ($result::class) {
                DSA2\PrivateKey::class => new DSA\PrivateKey(),
                DSA2\PublicKey::class => new DSA\PublicKey()
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
