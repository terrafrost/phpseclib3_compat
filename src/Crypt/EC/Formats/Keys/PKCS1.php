<?php

/**
 * "PKCS1" (RFC5915) Formatted EC Key Handler
 *
 * PHP version 8.1+
 *
 * Used by File/X509.php
 *
 * Processes keys with the following headers:
 *
 * -----BEGIN EC PRIVATE KEY-----
 * -----BEGIN EC PARAMETERS-----
 *
 * Technically, PKCS1 is for RSA keys, only, but we're using PKCS1 to describe
 * DSA, whose format isn't really formally described anywhere, so might as well
 * use it to describe this, too. PKCS1 is easier to remember than RFC5915, after
 * all. I suppose this could also be named IETF but idk
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib3\Crypt\EC\Formats\Keys;

use phpseclib4\Crypt\EC\Formats\Keys\PKCS1 as PKCS1New;

/**
 * "PKCS1" (RFC5915) Formatted EC Key Handler
 *
 * @method static array load()
 * @method static void setEncryptionAlgorithm(string $algo)
 * @method static void useSpecifiedCurve()
 * @method static void useNamedCurve()
 * @author Jim Wigginton <terrafrost@php.net>
 */
abstract class PKCS1
{
    public static function __callStatic(string $name, array $args): mixed
    {
        $r = PKCS1New::$name(...$args);
        \phpseclib3\File\ASN1::convertPrimitives($r);
        return $r;
    }
}