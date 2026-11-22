<?php

/**
 * PuTTY Formatted RSA Key Handler
 *
 * PHP version 8.1+
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib3\Crypt\RSA\Formats\Keys;

use phpseclib4\Crypt\RSA\Formats\Keys\PuTTY as PuTTYNew;

/**
 * PuTTY Formatted RSA Key Handler
 *
 * @method static void setComment()
 * @author Jim Wigginton <terrafrost@php.net>
 */
abstract class PuTTY
{
    public static function __callStatic(string $name, array $args): mixed
    {
        return PuTTYNew::$name(...$args);
    }
}