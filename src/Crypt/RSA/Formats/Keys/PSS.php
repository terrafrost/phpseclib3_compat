<?php

/**
 * PKCS#8 Formatted RSA-PSS Key Handler
 *
 * PHP version 8.1+
 *
 * Used by PHP's openssl_public_encrypt() and openssl's rsautl (when -pubin is set)
 *
 * Processes keys with the following headers:
 *
 * -----BEGIN ENCRYPTED PRIVATE KEY-----
 * -----BEGIN PRIVATE KEY-----
 * -----BEGIN PUBLIC KEY-----
 *
 * Analogous to "openssl genpkey -algorithm rsa-pss".
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib3\Crypt\RSA\Formats\Keys;

use phpseclib4\Crypt\RSA\Formats\Keys\PSS as PSSNew;

/**
 * PKCS#8 Formatted RSA-PSS Key Handler
 *
 * @method static array extractEncryptionAlgorithm(string $key)
 * @method static array load(string $key, string $password = '')
 * @method static void setPRF(string $algo)
 * @method static void setEncryptionAlgorithm(string $algo)
 * @method static void setEncryptionScheme(string $algo)
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class PSS
{
    public static function __callStatic(string $name, array $args): mixed
    {
        $r = PSSNew::$name(...$args);
        \phpseclib3\File\ASN1::convertPrimitives($r);
        return $r;
    }
}