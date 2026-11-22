<?php

/**
 * OpenSSH Formatted DSA Key Handler
 *
 * PHP version 8.1+
 *
 * Place in $HOME/.ssh/authorized_keys
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib3\Crypt\DSA\Formats\Keys;

use phpseclib4\Crypt\DSA\Formats\Keys\OpenSSH as OpenSSHNew;

/**
 * OpenSSH Formatted DSA Key Handler
 *
 * @method static void setComment()
 * @author Jim Wigginton <terrafrost@php.net>
 */
abstract class OpenSSH
{
    public static function __callStatic(string $name, array $args): mixed
    {
        return OpenSSHNew::$name(...$args);
    }
}
