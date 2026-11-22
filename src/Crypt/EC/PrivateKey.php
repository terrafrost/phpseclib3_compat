<?php

/**
 * EC Private Key
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      https://phpseclib.com/
 */

namespace phpseclib3\Crypt\EC;

use phpseclib3\Crypt\{Common, EC};

/**
 * EC Private Key
 *
 * @author Jim Wigginton <terrafrost@php.net>
 * @method string multiply(string $coordinates)
 */
final class PrivateKey extends EC implements Common\PrivateKey
{
}
