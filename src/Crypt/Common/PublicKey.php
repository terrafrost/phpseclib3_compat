<?php

/**
 * PublicKey interface
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      https://phpseclib.com/
 */

namespace phpseclib3\Crypt\Common;

/**
 * PublicKey interface
 *
 * @author Jim Wigginton <terrafrost@php.net>
 * @method bool verify(string $message, string $signature)
 * @method string toString(string $type, array $options)
 * @method string getFingerprint(string $algorithm)
 */
interface PublicKey
{
}
