<?php

/**
 * Base Class for all asymmetric key ciphers
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      https://phpseclib.com/
 */

namespace phpseclib3\Crypt\Common;

use phpseclib3\Crypt\Hash;

/**
 * Base Class for all asymmetric cipher classes
 *
 * @author Jim Wigginton <terrafrost@php.net>
 * @method Hash getHash()
 * @method AsymmetricKey withHash(string $hash)
 * @method static ?string getForcedEngine()
 * @method static void forceEngine(string $engine)
 * @method ?string getComment()
 * @method string getLoadedFormat()
 * @method static void addFileFormat(string $format)
 * @method static void setOpenSSLConfigPath(string $val)
 * @method static array getSupportedKeyFormats()
 * @method static AsymmetricKey loadParametersFormat(string $type, string $key)
 * @method static PublicKey loadPublicKeyFormat(string $type, string|array $key)
 * @method static PrivateKey loadPrivateKeyFormat(string $type, string|array $key, string|false $password = false)
 * @method static AsymmetricKey loadFormat(string $type, string|array $key, string|false $password = false)
 * @method static AsymmetricKey loadParameters(string $key)
 * @method static PublicKey loadPublicKey(string|array $key)
 * @method static PrivateKey loadPrivateKey(string|array $key)
 * @method static AsymmetricKey load(string|array $key, string|false $password = false)
 * @method string|array toString(string $type, array $options = [])
 */
abstract class AsymmetricKey
{
}
