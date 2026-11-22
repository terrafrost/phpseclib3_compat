<?php

/**
 * Wrapper around hash() and hash_hmac() functions supporting truncated hashes
 * such as sha256-96.  Any hash algorithm returned by hash_algos() (and
 * truncated versions thereof) are supported.
 *
 * If {@link self::setKey() setKey()} is called, {@link self::hash() hash()} will
 * return the HMAC as opposed to the hash.
 *
 * Here's a short example of how to use this library:
 * <code>
 * <?php
 *    include 'vendor/autoload.php';
 *
 *    $hash = new \phpseclib3\Crypt\Hash('sha512');
 *
 *    $hash->setKey('abcdefg');
 *
 *    echo base64_encode($hash->hash('abcdefg'));
 * ?>
 * </code>
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2015 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib3\Crypt;

use phpseclib4\Crypt\Hash as Hash2;

/**
 * We can't extend Hash2 because of stuff like setNonce() and setKey() which, in phpseclib 4, accepts
 * ?string, whereas in phpseclib 3 it accepted string|false.
 *
 * @author Jim Wigginton <terrafrost@php.net>
 * @author Andreas Fischer <bantu@phpbb.com>
 * @method int getLength()
 * @method int getLengthInBytes()
 * @method int getBlockLengthInBytes()
 * @method void setPassword(string $password, string $salt, int $iterationCount)
 * @method void setHash(string $hash)
 * @method void setKey(string|false $key)
 * @method void setNonce(string|false $nonce)
 * @method string getHash()
 * @method string hash(string|resource $text)
 */
class Hash
{
    private Hash2 $hash;

    public function __construct(string $hash = 'sha256')
    {
        $this->hash = new Hash2($hash);
    }

    public function __call(string $name, array $args): mixed
    {
        if (in_array($name, ['setKey, setNonce']) && $args[0] === false) {
            $args[0] = null;
        }
        $result = $this->hash->$name(...$args);
        return $result;
    }
}
