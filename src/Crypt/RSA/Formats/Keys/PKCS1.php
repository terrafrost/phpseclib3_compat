<?php

/**
 * PKCS#1 Formatted RSA Key Handler
 *
 * PHP version 8.1+
 *
 * Used by File/X509.php
 *
 * Processes keys with the following headers:
 *
 * -----BEGIN RSA PRIVATE KEY-----
 * -----BEGIN RSA PUBLIC KEY-----
 *
 * Analogous to ssh-keygen's pem format (as specified by -m)
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib3\Crypt\RSA\Formats\Keys;

use phpseclib4\Crypt\RSA\Formats\Keys\PKCS1 as PKCS1New;

/**
 * PKCS#1 Formatted RSA Key Handler
 *
 * @method static array load()
 * @method static void setEncryptionAlgorithm(string $algo)
 * @author Jim Wigginton <terrafrost@php.net>
 */
abstract class PKCS1
{
    public static function __callStatic(string $name, array $args): mixed
    {
        array_walk_recursive($args, function (&$value) {
            if ($value instanceof \phpseclib3\Math\BigInteger) {
                $value = new \phpseclib4\Math\Biginteger("$value");
            }
        });
        $r = PKCS1New::$name(...$args);
        \phpseclib3\File\ASN1::convertPrimitives($r);
        return $r;
    }
}