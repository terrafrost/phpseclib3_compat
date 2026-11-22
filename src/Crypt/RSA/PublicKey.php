<?php

/**
 * RSA Public Key
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      https://phpseclib.com/
 */

namespace phpseclib3\Crypt\RSA;

use phpseclib3\Crypt\{Common, RSA};

/**
 * RSA Public Key
 *
 * @author Jim Wigginton <terrafrost@php.net>
 * @method string encrypt(string $plaintext)
 * @method RSA asPrivateKey()
 */
final class PublicKey extends RSA implements Common\PublicKey
{
}
