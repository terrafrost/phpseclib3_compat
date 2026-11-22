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
    /**
     * Verifies a signature
     *
     * @see self::sign()
     */
    public function verify(string $message, string $signature): bool
    {
        // for now let's try SIGNATURE_PKCS1 for SIGNATURE_RELAXED_PKCS1
        // if that doesn't work this is where we'll need to add support for it
        //if ($this->origPadding & self::SIGNATURE_RELAXED_PKCS1) {
        //}
        return $this->key->verify($message, $signature);
    }
}
