<?php

/**
 * PublicKeyLoader
 *
 * Returns a PublicKey or PrivateKey object.
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib3\Crypt;

use phpseclib3\Crypt\Common\{AsymmetricKey, PrivateKey, PublicKey};
use phpseclib3\Exception\NoKeyLoadedException;
use phpseclib3\File\X509;

/**
 * PublicKeyLoader
 *
 * @author Jim Wigginton <terrafrost@php.net>
 */
abstract class PublicKeyLoader
{
    /**
     * Loads a public or private key
     */
    public static function load(string|array $key, string|bool $password = false): AsymmetricKey
    {
        try {
            return EC::load($key, $password);
        } catch (NoKeyLoadedException) {
        }

        try {
            return RSA::load($key, $password);
        } catch (NoKeyLoadedException) {
        }

        try {
            return DSA::load($key, $password);
        } catch (NoKeyLoadedException) {
        }

        try {
            $x509 = new X509();
            $x509->loadX509($key);
            $key = $x509->getPublicKey();
            if ($key) {
                return $key;
            }
        } catch (\Throwable) {
        }

        throw new NoKeyLoadedException('Unable to read key');
    }

    /**
     * Loads a private key
     */
    public static function loadPrivateKey(string|array $key, string|bool $password = false): PrivateKey
    {
        $key = self::load($key, $password);
        if (!$key instanceof PrivateKey) {
            throw new NoKeyLoadedException('The key that was loaded was not a private key');
        }
        return $key;
    }

    /**
     * Loads a public key
     */
    public static function loadPublicKey(string $key): PublicKey
    {
        $key = self::load($key);
        if (!$key instanceof PublicKey) {
            throw new NoKeyLoadedException('The key that was loaded was not a public key');
        }
        return $key;
    }

    /**
     * Loads parameters
     */
    public static function loadParameters(string $key): AsymmetricKey
    {
        $key = self::load($key);
        if (!$key instanceof PrivateKey && !$key instanceof PublicKey) {
            throw new NoKeyLoadedException('The key that was loaded was not a parameter');
        }
        return $key;
    }
}
