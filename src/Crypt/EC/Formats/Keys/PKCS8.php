<?php

/**
 * PKCS#8 Formatted EC Key Handler
 *
 * PHP version 8.1+
 *
 * Processes keys with the following headers:
 *
 * -----BEGIN ENCRYPTED PRIVATE KEY-----
 * -----BEGIN PRIVATE KEY-----
 * -----BEGIN PUBLIC KEY-----
 *
 * Analogous to ssh-keygen's pkcs8 format (as specified by -m). Although PKCS8
 * is specific to private keys it's basically creating a DER-encoded wrapper
 * for keys. This just extends that same concept to public keys (much like ssh-keygen)
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib3\Crypt\EC\Formats\Keys;

use phpseclib4\Crypt\EC\Formats\Keys\PKCS8 as PKCS8New;

/**
 * PKCS#8 Formatted EC Key Handler
 *
 * @method static void useSpecifiedCurve()
 * @method static void useNamedCurve()
 * @method static array extractEncryptionAlgorithm(string $key)
 * @method static array load(string $key, string $password = '')
 * @method static void setPRF(string $algo)
 * @method static void setEncryptionAlgorithm(string $algo)
 * @method static void setEncryptionScheme(string $algo)
 * @author Jim Wigginton <terrafrost@php.net>
 */
abstract class PKCS8
{
    public static function __callStatic(string $name, array $args): mixed
    {
        $r = PKCS8New::$name(...$args);
        \phpseclib3\File\ASN1::convertPrimitives($r);
        return $r;
    }
}