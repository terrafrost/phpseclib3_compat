<?php

/**
 * Base Class for all \phpseclib3\Crypt\* cipher classes
 *
 * PHP version 8.1
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @author    Hans-Juergen Petrich <petrich@tronic-media.com>
 * @copyright 2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib3\Crypt\Common;

/**
 * Base Class for all \phpseclib3\Crypt\* cipher classes
 *
 * @author Jim Wigginton <terrafrost@php.net>
 * @author Hans-Juergen Petrich <petrich@tronic-media.com>
 */
abstract class SymmetricKey
{
    public const MODE_CTR = -1;
    public const MODE_ECB = 1;
    public const MODE_CBC = 2;
    public const MODE_CFB = 3;
    public const MODE_CFB8 = 7;
    public const MODE_OFB8 = 8;
    public const MODE_OFB = 4;
    public const MODE_GCM = 5;
    public const MODE_STREAM = 6;

    public const ENGINE_INTERNAL = 1;
    public const ENGINE_EVAL = 2;
    public const ENGINE_MCRYPT = 3;
    public const ENGINE_OPENSSL = 4;
    public const ENGINE_LIBSODIUM = 5;
    public const ENGINE_OPENSSL_GCM = 6;
}