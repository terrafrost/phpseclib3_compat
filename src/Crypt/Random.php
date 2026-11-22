<?php

/**
 * Random Number Generator
 *
 * PHP version 8.1+
 *
 * Here's a short example of how to use this library:
 * <code>
 * <?php
 *    include 'vendor/autoload.php';
 *
 *    echo bin2hex(\phpseclib3\Crypt\Random::string(8));
 * ?>
 * </code>
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib3\Crypt;

/**
 * Pure-PHP Random Number Generator
 *
 * @author Jim Wigginton <terrafrost@php.net>
 */
abstract class Random
{
    /**
     * Generate a random string.
     *
     * Although microoptimizations are generally discouraged as they impair readability this function is ripe with
     * microoptimizations because this function has the potential of being called a huge number of times.
     * eg. for RSA key generation.
     *
     * @param int $length
     * @throws \RuntimeException if a symmetric cipher is needed but not loaded
     * @return string
     */
    public static function string(int $length): string
    {
        if (!$length) {
            return '';
        }

        return random_bytes($length);
    }
}
