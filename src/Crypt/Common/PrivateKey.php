<?php

/**
 * PrivateKey interface
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      https://phpseclib.com/
 */

namespace phpseclib3\Crypt\Common;

/**
 * PrivateKey interface
 *
 * @author Jim Wigginton <terrafrost@php.net>
 * @method string sign(string $message)
 * @method PublicKey getPublicKey()
 * @method string toString(string $type, array $options = [])
 * @method PrivateKey withPassword(string|false $password = false)
 */
interface PrivateKey
{
}
