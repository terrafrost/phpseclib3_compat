<?php

/**
 * PuTTY Formatted EC Key Handler
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib3\Crypt\EC\Formats\Keys;

use phpseclib4\Crypt\EC\Formats\Keys\PuTTY as PuTTYNew;

/**
 * PuTTY Formatted EC Key Handler
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