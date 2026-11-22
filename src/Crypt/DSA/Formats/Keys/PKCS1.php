<?php

/**
 * PKCS#1 Formatted DSA Key Handler
 *
 * PHP version 8.1+
 *
 * Used by File/X509.php
 *
 * Processes keys with the following headers:
 *
 * -----BEGIN DSA PRIVATE KEY-----
 * -----BEGIN DSA PUBLIC KEY-----
 * -----BEGIN DSA PARAMETERS-----
 *
 * Analogous to ssh-keygen's pem format (as specified by -m)
 *
 * Also, technically, PKCS1 decribes RSA but I am not aware of a formal specification for DSA.
 * The DSA private key format seems to have been adapted from the RSA private key format so
 * we're just re-using that as the name.
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib3\Crypt\DSA\Formats\Keys;

use phpseclib4\Crypt\DSA\Formats\Keys\PKCS1 as PKCS1New;

/**
 * PKCS#1 Formatted DSA Key Handler
 *
 * @method static array load()
 * @method static void setEncryptionAlgorithm(string $algo)
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