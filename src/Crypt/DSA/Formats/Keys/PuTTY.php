<?php

/**
 * PuTTY Formatted DSA Key Handler
 *
 * puttygen does not generate DSA keys with an N of anything other than 160, however,
 * it can still load them and convert them. PuTTY will load them, too, but SSH servers
 * won't accept them. Since PuTTY formatted keys are primarily used with SSH this makes
 * keys with N > 160 kinda useless, hence this handlers not supporting such keys.
 *
 * PHP version 8.1+
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib3\Crypt\DSA\Formats\Keys;

use phpseclib4\Crypt\DSA\Formats\Keys\PuTTY as PuTTYNew;

/**
 * PuTTY Formatted DSA Key Handler
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