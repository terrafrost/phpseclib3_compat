<?php

/**
 * Pure-PHP X.509 Parser
 *
 * Encode and decode X.509 certificates.
 *
 * The extensions are from {@link http://tools.ietf.org/html/rfc5280 RFC5280} and
 * {@link http://web.archive.org/web/19961027104704/http://www3.netscape.com/eng/security/cert-exts.html Netscape Certificate Extensions}.
 *
 * Note that loading an X.509 certificate and resaving it may invalidate the signature.  The reason being that the signature is based on a
 * portion of the certificate that contains optional parameters with default values.  ie. if the parameter isn't there the default value is
 * used.  Problem is, if the parameter is there and it just so happens to have the default value there are two ways that that parameter can
 * be encoded.  It can be encoded explicitly or left out all together.  This would effect the signature value and thus may invalidate the
 * the certificate all together unless the certificate is re-signed.
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      https://phpseclib.com/
 */

declare(strict_types=1);

namespace phpseclib3\File;

use phpseclib3\Math\BigInteger;
use phpseclib3\File\ASN1\Element;
use phpseclib3\Crypt\{Common\PrivateKey, Common\PublicKey, EC, DSA, RSA};
use phpseclib3\Exception\UnsupportedAlgorithmException;

use phpseclib4\Common\Functions\Arrays;
use phpseclib4\Crypt\{Hash, PublicKeyLoader, RSA as NewRSA};
use phpseclib4\Crypt\Common\PublicKey as NewPublicKey;
use phpseclib4\Exception\{CharacterConversionException,
    InvalidStateException,
    UnsupportedAlgorithmException as NewUnsupportedAlgorithmException};
use phpseclib4\File\ASN1\Element as NewElement;
use phpseclib4\File\{ASN1 as NewASN1, X509 as NewX509, CRL, CSR, SPKAC};
use phpseclib4\File\ASN1\Types\{BaseString, BaseType, Choice, OID, UTF8String};
use phpseclib4\File\ASN1\Maps;
use phpseclib4\Math\BigInteger as NewBigInteger;

/**
 * Pure-PHP X.509 Parser
 *
 * @author Jim Wigginton <terrafrost@php.net>
 */
class X509
{
    use \phpseclib4\File\Common\Traits\ASN1Signature;

    private ?array $currentCert = null;
    private ?string $signatureSubject = null;
    private ?array $dn = null;
    private static int $recur_limit = 5;
    private static bool $disable_url_fetch = false;
    private array $CAs = [];
    private ?string $currentKeyIdentifier = null;
    private ?PublicKey $publicKey = null;
    private PrivateKey $privateKey;
    private bool $caFlag = false;
    private string $startDate;
    private string|Element $endDate;
    private ?array $domains = null;
    private static array $extensions = [];
    private array $extensionValues = [];
    private string $challenge;
    private BigInteger $serialNumber;
    private ?array $ipAddresses = null;
    private static bool $urlFetchCallbackSet = false;

    private static int|float $urlFetchTimeout = 10;
    private static ?float $urlFetchDeadline = null;

    /**
     * Return internal array representation
     */
    const DN_ARRAY = 0;
    /**
     * Return string
     */
    const DN_STRING = 1;
    /**
     * Return ASN.1 name string
     */
    const DN_ASN1 = 2;
    /**
     * Return OpenSSL compatible array
     */
    const DN_OPENSSL = 3;
    /**
     * Return canonical ASN.1 RDNs string
     */
    const DN_CANON = 4;
    /**
     * Return name hash for file indexing
     */
    const DN_HASH = 5;

    /**
     * Save as PEM
     *
     * ie. a base64-encoded PEM with a header and a footer
     */
    public const FORMAT_PEM = 0;
    /**
     * Save as DER
     */
    public const FORMAT_DER = 1;
    /**
     * Save as a SPKAC
     *
     * Only works on CSRs. Not currently supported.
     */
    public const FORMAT_SPKAC = 2;
    /**
     * Auto-detect the format
     *
     * Used only by the load*() functions
     */
    public const FORMAT_AUTO_DETECT = 3;

    /**
     * Attribute value disposition.
     * If disposition is >= 0, this is the index of the target value.
     */
    const ATTR_ALL = -1; // All attribute values (array).
    const ATTR_APPEND = -2; // Add a value.
    const ATTR_REPLACE = -3; // Clear first, then add a value.

    /**
     * Default Constructor.
     */
    public function __construct()
    {
        if (!static::$urlFetchCallbackSet) {
            NewX509::setURLFetchCallback(fn () => true);
            static::$urlFetchCallbackSet = true;
        }
    }

    private static function map(mixed &$value): void
    {
        if (!is_object($value)) {
            return;
        }
        if ($value instanceof NewElement) {
            $value = new Element($value->value);
            return;
        }
        $shortClass = (new \ReflectionClass($value))->getShortName();
        $value = match ($shortClass) {
            'OID' => (string) $value,
            'Integer' => isset($value->mappedValue) ?
                (string) $value :
                new BigInteger("$value"),
            'ExplicitNull' => ['null' => null],
            'PrintableString' => ['printableString' => "$value"],
            'TeletexString' => ['teletexString' => "$value"],
            'IA5String' => ['ia5String' => "$value"],
            'GraphicString' => ['graphicString' => "$value"],
            'UTF8String' => ['utf8String' => "$value"],
            'VideotexString' => ['videotexString' => "$value"],
            'VisibleString' => ['visibleString' => "$value"],
            'BMPString' => ['bmpString' => "$value"],
            'UTCTime', 'GeneralizedTime' => $value->format(ASN1::$format),
            'Boolean' => (bool) $value->value,
            'BitString' => isset($value->mappedValue) ?
                $value->toArray() :
                $value->value,
            'OctetString' => $value->value,
            'PublicKey' => (string) $value,
            'Element' => new Element("$value"),
            default => $value
        };
    }

    private static function convertToV4(mixed $value): mixed
    {
        if (is_object($value)) {
            return match (get_class($value)) {
                BigInteger::class => new NewBigInteger((string) $value),
                Element::class    => new NewElement($value->element),
                default               => $value,
            };
        }

        if (!is_array($value)) {
            return $value;
        }

        if (count($value) === 1) {
            $key = array_key_first($value);
            $val = $value[$key];

            if (is_string($val) || $key == 'null') {
                $unmapped = match ($key) {
                    'null'            => new \phpseclib4\File\ASN1\Types\ExplicitNull(),
                    'printableString' => new \phpseclib4\File\ASN1\Types\PrintableString($val),
                    'teletexString'   => new \phpseclib4\File\ASN1\Types\TeletexString($val),
                    'ia5String'       => new \phpseclib4\File\ASN1\Types\IA5String($val),
                    'graphicString'   => new \phpseclib4\File\ASN1\Types\GraphicString($val),
                    'utf8String'      => new \phpseclib4\File\ASN1\Types\UTF8String($val),
                    'videotexString'  => new \phpseclib4\File\ASN1\Types\VideotexString($val),
                    'visibleString'   => new \phpseclib4\File\ASN1\Types\VisibleString($val),
                    'bmpString'       => new \phpseclib4\File\ASN1\Types\BMPString($val),
                    default           => null,
                };

                if ($unmapped !== null) {
                    return $unmapped;
                }
            }
        }

        foreach ($value as $key => $subValue) {
            $value[$key] = self::convertToV4($subValue);
        }

        return $value;
    }

    private static function convertDNtoPostV3(array &$array): void
    {
        foreach ($array as &$dn) {
            foreach ($dn as &$subdn) {
                if ($subdn['type'] == 'id-at-postalAddress') {
                    foreach ($subdn['value'] as &$part) {
                        $key = array_key_first($part);
                        $part[$key] = $part[$key][$key];
                    }
                    unset($part);
                }
            }
            unset($subdn);
        }
    }

    private static function convertDNtoPreV4(array &$arr): void
    {
        foreach ($arr as &$subarr) {
            foreach ($subarr as &$dn) {
                foreach ($dn as &$subdn) {
                    if ($subdn['type'] == 'id-at-postalAddress') {
                        foreach ($subdn['value'] as &$part) {
                            $key = array_key_first($part);
                            $part[$key] = [$key => $part[$key]];
                        }
                        unset($part);
                    }
                }
                unset($subdn);
            }
        }
    }

    private static function convertExtToPostV3(array &$array): void
    {
        foreach ($array as &$ext) {
            try {
                switch ($ext['extnId']) {
                    case 'id-ce-cRLDistributionPoints':
                        Arrays::subArrayMapWithWildcards($ext['extnValue'], '*/distributionPoint/fullName/*/uniformResourceIdentifier', fn ($val) => $val['ia5String']);
                        break;
                    case 'id-ce-subjectAltName':
                        Arrays::subArrayMapWithWildcards($ext['extnValue'], '*/dNSName', fn ($val) => $val['ia5String']);
                        Arrays::subArrayMapWithWildcards($ext['extnValue'], '*/rfc822Name', fn ($val) => $val['ia5String']);
                        Arrays::subArrayMapWithWildcards($ext['extnValue'], '*/uniformResourceIdentifier', fn ($val) => $val['ia5String']);
                        break;
                    case 'id-pe-authorityInfoAccess':
                        Arrays::subArrayMapWithWildcards($ext['extnValue'], '*/accessLocation/dNSName', fn ($val) => $val['ia5String']);
                        Arrays::subArrayMapWithWildcards($ext['extnValue'], '*/accessLocation/rfc822Name', fn ($val) => $val['ia5String']);
                        Arrays::subArrayMapWithWildcards($ext['extnValue'], '*/accessLocation/uniformResourceIdentifier', fn ($val) => $val['ia5String']);
                        break;
                    case 'id-pe-logotype':
                        Arrays::subArrayMapWithWildcards($ext['extnValue'], 'subjectLogo/direct/image/*/imageDetails/mediaType', fn ($val) => $val['ia5String']);
                }
            } catch (\Error) {
            }
            if ($ext['extnValue'] instanceof Element) {
                $ext['extnValue'] = $ext['extnValue']->element;
            }
        }
    }

    /**
     * Get the Distinguished Name for a certificates subject
     */
    public function getDN(int $format = self::DN_ARRAY, ?array $dn = null): array|bool|string
    {
        if (!isset($dn)) {
            $dn = isset($this->currentCert['tbsCertList']) ? $this->currentCert['tbsCertList']['issuer'] : $this->dn;
        }

        if ($format == self::DN_ARRAY) {
            return $dn;
        }

        self::convertDNtoPreV4($dn);
        $dn = self::convertToV4($dn);

        $method = new \ReflectionMethod(NewX509::class, 'formatDN');

        switch ($format) {
            case self::DN_ASN1:
            case self::DN_CANON:
            case self::DN_HASH:
                return $method->invoke(null, $dn, $format);
        }

        $encoded = $method->invoke(null, $dn, self::DN_ASN1);
        $decoded = NewASN1::decodeBER($encoded);
        $dn = NewASN1::map($decoded, Maps\Name::MAP);

        // Default is to return a string.
        $start = true;
        $output = '';

        $result = [];
        foreach ($dn['rdnSequence'] as $field) {
            $prop = $field[0]['type'];
            $value = $field[0]['value'];
            $delim = ', ';
            switch ($prop) {
                case 'id-at-countryName':
                    $desc = 'C';
                    break;
                case 'id-at-stateOrProvinceName':
                    $desc = 'ST';
                    break;
                case 'id-at-organizationName':
                    $desc = 'O';
                    break;
                case 'id-at-organizationalUnitName':
                    $desc = 'OU';
                    break;
                case 'id-at-commonName':
                    $desc = 'CN';
                    break;
                case 'id-at-localityName':
                    $desc = 'L';
                    break;
                case 'id-at-surname':
                    $desc = 'SN';
                    break;
                case 'id-at-uniqueIdentifier':
                    $delim = '/';
                    $desc = 'x500UniqueIdentifier';
                    break;
                case 'id-at-postalAddress':
                    $delim = '/';
                    $desc = 'postalAddress';
                    break;
                default:
                    $delim = '/';
                    $desc = preg_replace('#.+-([^-]+)$#', '$1', "$prop");
            }

            if (!$start) {
                $output .= $delim;
            }

            if ($value instanceof NewElement) {
                $value = strtoupper(preg_replace_callback('#[^\x20-\x7E]#', fn ($x) => '\x' . bin2hex($x[0]), "$value"));
            } elseif ($value instanceof BaseString && $value->isConvertable()) {
                try {
                    $value = $value->toUTF8String();
                } catch (CharacterConversionException) {
                    $value = $value->value;
                }
            }

            $output .= $desc . '=' . $value;
            $result[$desc] = isset($result[$desc]) ?
                array_merge($result[$desc], ["$value"]) :
                ["$value"];
            $start = false;
        }

        return $format == self::DN_OPENSSL ? $result : $output;
    }

    /**
     * Get the Distinguished Name for a certificate/crl issuer
     */
    public function getIssuerDN(int $format = self::DN_ARRAY): string|array|bool
    {
        switch (true) {
            case !isset($this->currentCert) || !is_array($this->currentCert):
                break;
            case isset($this->currentCert['tbsCertificate']):
                return $this->getDN($format, $this->currentCert['tbsCertificate']['issuer']);
            case isset($this->currentCert['tbsCertList']):
                return $this->getDN($format, $this->currentCert['tbsCertList']['issuer']);
        }

        return false;
    }

    /**
     * Get the Distinguished Name for a certificate/csr subject
     * Alias of getDN()
     */
    public function getSubjectDN(int $format = self::DN_ARRAY): string|array|bool
    {
        switch (true) {
            case !empty($this->dn):
                return $this->getDN($format);
            case !isset($this->currentCert) || !is_array($this->currentCert):
                break;
            case isset($this->currentCert['tbsCertificate']):
                return $this->getDN($format, $this->currentCert['tbsCertificate']['subject']);
            case isset($this->currentCert['certificationRequestInfo']):
                return $this->getDN($format, $this->currentCert['certificationRequestInfo']['subject']);
        }

        return false;
    }

    /**
     * Get Distinguished Name properties
     */
    public function getDNProp(string $propName, ?array $dn = null, bool $withType = false): bool|array
    {
        if (!isset($dn)) {
            $dn = $this->dn;
        }

        if (empty($dn)) {
            return false;
        }

        try {
            $method = new \ReflectionMethod(NewX509::class, 'translateDNProp');
            $propName = $method->invoke(null, $propName);
        } catch (\Exception) {
            return false;
        }

        $result = [];
        $origDN = $dn;
        self::convertDNtoPreV4($dn);
        $dn = self::convertToV4($dn);
        for ($i = 0; $i < count($dn['rdnSequence']); $i++) {
            if ($dn['rdnSequence'][$i][0]['type'] == $propName) {
                $v = $dn['rdnSequence'][$i][0]['value'];
                if (!$withType) {
                    if ($v instanceof BaseString && $v->isConvertable()) {
                        $v = (string) $v->toUTF8String();
                    } elseif (is_array($v)) {
                        $v = $origDN['rdnSequence'][$i][0]['value'];
                    }
                } elseif (!is_array($v)) {
                    $v = $origDN['rdnSequence'][$i][0]['value'];
                } else {
                    if (!isset($encodedDN)) {
                        $method = new \ReflectionMethod(NewX509::class, 'formatDN');
                        $encoded = $method->invoke(null, $dn, self::DN_ASN1);
                        $decoded = NewASN1::decodeBER($encoded);
                        $encodedDN = NewASN1::map($decoded, Maps\Name::MAP);
                    }
                    $v = $encodedDN['rdnSequence'][$i][0]['value'];
                    if ($v instanceof NewElement) {
                        $v = new Element("$v");
                    }
                }
                $result[] = $v;
            }
        }

        return $result;
    }

    /**
     * Get an individual Distinguished Name property for a certificate/csr subject
     */
    public function getSubjectDNProp(string $propName, bool $withType = false): array|bool
    {
        switch (true) {
            case !empty($this->dn):
                return $this->getDNProp($propName, null, $withType);
            case !isset($this->currentCert) || !is_array($this->currentCert):
                break;
            case isset($this->currentCert['tbsCertificate']):
                return $this->getDNProp($propName, $this->currentCert['tbsCertificate']['subject'], $withType);
            case isset($this->currentCert['certificationRequestInfo']):
                return $this->getDNProp($propName, $this->currentCert['certificationRequestInfo']['subject'], $withType);
        }

        return false;
    }

    /**
     * Get an individual Distinguished Name property for a certificate/crl issuer
     */
    public function getIssuerDNProp(string $propName, bool $withType = false): array|bool
    {
        switch (true) {
            case !isset($this->currentCert) || !is_array($this->currentCert):
                break;
            case isset($this->currentCert['tbsCertificate']):
                return $this->getDNProp($propName, $this->currentCert['tbsCertificate']['issuer'], $withType);
            case isset($this->currentCert['tbsCertList']):
                return $this->getDNProp($propName, $this->currentCert['tbsCertList']['issuer'], $withType);
        }

        return false;
    }

    private function convertPublicKey(string $path, NewX509|SPKAC|CSR $constructed): void
    {
        $key = &Arrays::subArray($this->currentCert, $path);
        if (!$key instanceof NewPublicKey) {
            $key['subjectPublicKey'] =
                "-----BEGIN PUBLIC KEY-----\r\n" .
                chunk_split(base64_encode(Arrays::subArray($constructed, $path)->getEncoded())) .
                "-----END PUBLIC KEY-----";
        } else {
            if ($key instanceof NewRSA && ($key->getPadding() & NewRSA::SIGNATURE_PSS)) {
                $raw = $key->toString('PSS');
            } else {
                $raw = (string) $key;
            }
            $encoded = NewASN1::extractBER($raw);
            $decoded = NewASN1::decodeBER($encoded);
            $public = NewASN1::map($decoded, Maps\PublicKeyInfo::MAP)->toArray();
            $key = [
                'algorithm' => $public['publicKeyAlgorithm'],
                'subjectPublicKey' => $raw
            ];
        }
    }

    /**
     * Load X.509 certificate
     *
     * Returns an associative array describing the X.509 cert or a false if the cert failed to load
     */
    public function loadX509(string|array $cert, int $mode = self::FORMAT_AUTO_DETECT): bool|array
    {
        if (is_array($cert)) {
            unset($this->currentCert);
            unset($this->currentKeyIdentifier);
            $this->dn = $cert['tbsCertificate']['subject'];
            if (!isset($this->dn)) {
                return false;
            }
            $this->currentCert = $cert;
            $currentKeyIdentifier = $this->getExtension('id-ce-subjectKeyIdentifier');
            $this->currentKeyIdentifier = is_string($currentKeyIdentifier) ? $currentKeyIdentifier : null;
            unset($this->signatureSubject);
            return $cert;
        }
        try {
            $constructed = NewX509::load($cert, $mode);
            $this->signatureSubject = $constructed['tbsCertificate']->getEncoded();
            $this->currentCert = $constructed->toArray();
        } catch (\Exception $e) {
            unset($this->currentCert, $this->signatureSubject);
            return false;
        }
        $this->convertPublicKey('tbsCertificate/subjectPublicKeyInfo', $constructed);

        array_walk_recursive($this->currentCert, self::map(...));
        self::convertDNtoPostV3($this->currentCert['tbsCertificate']['subject']['rdnSequence']);
        self::convertDNtoPostV3($this->currentCert['tbsCertificate']['issuer']['rdnSequence']);
        if (isset($this->currentCert['tbsCertificate']['extensions'])) {
            self::convertExtToPostV3($this->currentCert['tbsCertificate']['extensions']);
        }
        $this->dn = $this->currentCert['tbsCertificate']['subject'];

        $currentKeyIdentifier = $this->getExtension('id-ce-subjectKeyIdentifier');
        $this->currentKeyIdentifier = is_string($currentKeyIdentifier) ? $currentKeyIdentifier : null;

        return $this->currentCert;
    }

    /**
     * Save X.509 certificate
     */
    public function saveX509(array $cert, int $format = self::FORMAT_PEM): string|bool
    {
        if (!isset($cert['tbsCertificate'])) {
            return false;
        }

        self::convertDNtoPreV4($cert['tbsCertificate']['subject']);
        self::convertDNtoPreV4($cert['tbsCertificate']['issuer']);

        foreach ($this->extensionValues as $id => $data) {
            $critical = $data['critical'];
            $replace = $data['replace'];
            $value = $data['value'];
            $newext = [
                'extnId' => $id,
                'extnValue' => $value,
                'critical' => $critical
            ];
            $cert['tbsCertificate']['extensions'][] = $newext;
        }

        $cert = self::convertToV4($cert);

        $cert['tbsCertificate']['subjectPublicKeyInfo'] = new NewElement(
            base64_decode(preg_replace('#-.+-|[\r\n]#', '', $cert['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey']))
        );

        $writer = new NewX509();
        $ref = new \ReflectionObject($writer);
        $prop = $ref->getProperty('cert');
        $prop->setValue($writer, $cert);

        return $writer->toString(['binary' => $format === self::FORMAT_DER]);
    }

    /**
     * Gets the public key
     *
     * Returns a \phpseclib3\Crypt\RSA object or a false.
     */
    public function getPublicKey(): PublicKey|bool
    {
        if (isset($this->publicKey)) {
            return $this->publicKey;
        }

        if (isset($this->currentCert) && is_array($this->currentCert)) {
            $paths = [
                'tbsCertificate/subjectPublicKeyInfo',
                'certificationRequestInfo/subjectPKInfo',
                'publicKeyAndChallenge/spki'
            ];
            foreach ($paths as $path) {
                $keyinfo = Arrays::subArray($this->currentCert, $path);
                if (!empty($keyinfo)) {
                    break;
                }
            }
        }
        if (empty($keyinfo)) {
            return false;
        }

        $key = $keyinfo['subjectPublicKey'];

        try {
            return match ((string) $keyinfo['algorithm']['algorithm']) {
                'id-RSASSA-PSS' => RSA::loadFormat('PSS', $key),
                'rsaEncryption' => RSA::loadFormat('PKCS8', $key)->withPadding(RSA::SIGNATURE_PKCS1),
                'id-ecPublicKey', 'id-Ed25519', 'id-Ed448' => EC::loadFormat('PKCS8', $key),
                'id-dsa' => DSA::loadFormat('PKCS8', $key),
                default => false
            };
        } catch (\Exception $e) {
            throw new \RuntimeException($e->getMessage());
        }
    }

    /**
     * Get a reference to an extension subarray
     */
    private function &extensions(?array &$root, ?string $path = null, bool $create = false): array|bool
    {
        if (!isset($root)) {
            $root = $this->currentCert;
        }

        switch (true) {
            case !empty($path):
            case !is_array($root):
                break;
            case isset($root['tbsCertificate']):
                $path = 'tbsCertificate/extensions';
                break;
            case isset($root['tbsCertList']):
                $path = 'tbsCertList/crlExtensions';
                break;
            case isset($root['certificationRequestInfo']):
                $pth = 'certificationRequestInfo/attributes';
                $attributes = &Arrays::subArray($root, $pth, $create);

                if (is_array($attributes)) {
                    foreach ($attributes as $key => $value) {
                        if ($value['type'] == 'pkcs-9-at-extensionRequest') {
                            $path = "$pth/$key/value/0";
                            break 2;
                        }
                    }
                    if ($create) {
                        $key = count($attributes);
                        $attributes[] = ['type' => 'pkcs-9-at-extensionRequest', 'value' => []];
                        $path = "$pth/$key/value/0";
                    }
                }
                break;
        }

        $extensions = &Arrays::subArray($root, $path, $create);

        if (!is_array($extensions)) {
            $false = false;
            return $false;
        }

        return $extensions;
    }

    /**
     * Returns a list of all extensions in use
     */
    private function getExtensionsHelper(?array $cert = null, ?string $path = null): array
    {
        $exts = $this->extensions($cert, $path);
        $extensions = [];

        if (is_array($exts)) {
            foreach ($exts as $extension) {
                $extensions[] = $extension['extnId'];
            }
        }

        return $extensions;
    }

    /**
     * Returns a list of all extensions in use in certificate, CSR or CRL
     */
    public function getExtensions(?array $cert = null, ?string $path = null): array
    {
        return $this->getExtensionsHelper($cert, $path);
    }

    /**
     * Get a certificate, CSR or CRL Extension
     *
     * Returns the extension if it exists and false if not
     */
    public function getExtension(string $id, ?array $cert = null, ?string $path = null): string|array|bool
    {
        return $this->getExtensionHelper($id, $cert, $path);
    }

    /**
     * Get an Extension
     *
     * Returns the extension if it exists and false if not
     */
    private function getExtensionHelper(string $id, ?array $cert = null, ?string $path = null): string|array|bool
    {
        $extensions = $this->extensions($cert, $path);

        if (!is_array($extensions)) {
            return false;
        }

        foreach ($extensions as $key => $value) {
            if ($value['extnId'] == $id) {
                return $value['extnValue'];
            }
        }

        return false;
    }

    /**
     * Validate an X.509 certificate against a URL
     *
     * From RFC2818 "HTTP over TLS":
     *
     * Matching is performed using the matching rules specified by
     * [RFC2459].  If more than one identity of a given type is present in
     * the certificate (e.g., more than one dNSName name, a match in any one
     * of the set is considered acceptable.) Names may contain the wildcard
     * character * which is considered to match any single domain name
     * component or component fragment. E.g., *.a.com matches foo.a.com but
     * not bar.foo.a.com. f*.com matches foo.com but not bar.com.
     */
    public function validateURL(string $url): bool
    {
        if (!is_array($this->currentCert) || !isset($this->currentCert['tbsCertificate'])) {
            return false;
        }

        $components = parse_url($url);
        if (!isset($components['host'])) {
            return false;
        }

        if ($names = $this->getExtension('id-ce-subjectAltName')) {
            foreach ($names as $name) {
                foreach ($name as $key => $value) {
                    $value = preg_quote($value, '#');
                    $value = str_replace('\*', '[^.]*', $value);
                    switch ($key) {
                        case 'dNSName':
                            /* From RFC2818 "HTTP over TLS":

                               If a subjectAltName extension of type dNSName is present, that MUST
                               be used as the identity. Otherwise, the (most specific) Common Name
                               field in the Subject field of the certificate MUST be used. Although
                               the use of the Common Name is existing practice, it is deprecated and
                               Certification Authorities are encouraged to use the dNSName instead. */
                            if (preg_match('#^' . $value . '$#', $components['host'])) {
                                return true;
                            }
                            break;
                        case 'iPAddress':
                            /* From RFC2818 "HTTP over TLS":

                               In some cases, the URI is specified as an IP address rather than a
                               hostname. In this case, the iPAddress subjectAltName must be present
                               in the certificate and must exactly match the IP in the URI. */
                            if (preg_match('#(?:\d{1-3}\.){4}#', $components['host'] . '.') && preg_match('#^' . $value . '$#', $components['host'])) {
                                return true;
                            }
                    }
                }
            }
            return false;
        }

        if ($value = $this->getDNProp('id-at-commonName')) {
            $value = preg_quote($value[0], '#');
            $value = str_replace('\*', '[^.]*', $value);
            return preg_match('#^' . $value . '$#', $components['host']) ? true : false;
        }

        return false;
    }

    /**
     * Validate a date
     *
     * If $date isn't defined it is assumed to be the current date.
     */
    public function validateDate(\DateTimeInterface|string|null $date = null): bool
    {
        if (!is_array($this->currentCert) || !isset($this->currentCert['tbsCertificate'])) {
            return false;
        }

        if (!isset($date)) {
            $date = new \DateTimeImmutable('now', new \DateTimeZone(@date_default_timezone_get()));
        }

        $notBefore = $this->currentCert['tbsCertificate']['validity']['notBefore'];
        $notBefore = isset($notBefore['generalTime']) ? $notBefore['generalTime'] : $notBefore['utcTime'];

        $notAfter = $this->currentCert['tbsCertificate']['validity']['notAfter'];
        $notAfter = isset($notAfter['generalTime']) ? $notAfter['generalTime'] : $notAfter['utcTime'];

        if (is_string($date)) {
            $date = new \DateTimeImmutable($date, new \DateTimeZone(@date_default_timezone_get()));
        }

        $notBefore = new \DateTimeImmutable($notBefore, new \DateTimeZone(@date_default_timezone_get()));
        $notAfter = new \DateTimeImmutable($notAfter, new \DateTimeZone(@date_default_timezone_get()));

        return $date >= $notBefore && $date <= $notAfter;
    }

    /**
     * Load an X.509 certificate as a certificate authority
     */
    public function loadCA(string $cert): bool
    {
        $olddn = $this->dn;
        $oldcert = $this->currentCert;
        $oldsigsubj = $this->signatureSubject;
        $oldkeyid = $this->currentKeyIdentifier;

        $cert = $this->loadX509($cert);
        if (!$cert) {
            $this->dn = $olddn;
            $this->currentCert = $oldcert;
            $this->signatureSubject = $oldsigsubj;
            $this->currentKeyIdentifier = $oldkeyid;

            return false;
        }

        /* From RFC5280 "PKIX Certificate and CRL Profile":

           If the keyUsage extension is present, then the subject public key
           MUST NOT be used to verify signatures on certificates or CRLs unless
           the corresponding keyCertSign or cRLSign bit is set. */
        //$keyUsage = $this->getExtension('id-ce-keyUsage');
        //if ($keyUsage && !in_array('keyCertSign', $keyUsage)) {
        //    return false;
        //}

        /* From RFC5280 "PKIX Certificate and CRL Profile":

           The cA boolean indicates whether the certified public key may be used
           to verify certificate signatures.  If the cA boolean is not asserted,
           then the keyCertSign bit in the key usage extension MUST NOT be
           asserted.  If the basic constraints extension is not present in a
           version 3 certificate, or the extension is present but the cA boolean
           is not asserted, then the certified public key MUST NOT be used to
           verify certificate signatures. */
        //$basicConstraints = $this->getExtension('id-ce-basicConstraints');
        //if (!$basicConstraints || !$basicConstraints['cA']) {
        //    return false;
        //}

        $this->CAs[] = $cert;

        $this->dn = $olddn;
        $this->currentCert = $oldcert;
        $this->signatureSubject = $oldsigsubj;

        return true;
    }

    /**
     * Validate a signature
     *
     * Works on X.509 certs, CSR's and CRL's.
     * Returns true if the signature is verified, false if it is not correct or null on error
     *
     * By default returns false for self-signed certs. Call validateSignature(false) to make this support
     * self-signed.
     *
     * The behavior of this function is inspired by {@link http://php.net/openssl-verify openssl_verify}.
     */
    public function validateSignature(bool $caonly = true): null|bool
    {
        return $this->validateSignatureCountable($caonly, 0);
    }

    /**
     * Validate a signature
     *
     * Performs said validation whilst keeping track of how many times validation method is called
     */
    private function validateSignatureCountable(bool $caonly, int $count): null|bool
    {
        if (!is_array($this->currentCert) || !isset($this->signatureSubject)) {
            return null;
        }

        if ($count == self::$recur_limit) {
            return false;
        }

        /* TODO:
           "emailAddress attribute values are not case-sensitive (e.g., "subscriber@example.com" is the same as "SUBSCRIBER@EXAMPLE.COM")."
            -- http://tools.ietf.org/html/rfc5280#section-4.1.2.6

           implement pathLenConstraint in the id-ce-basicConstraints extension */

        switch (true) {
            case isset($this->currentCert['tbsCertificate']):
                // self-signed cert
                switch (true) {
                    case !defined('FILE_X509_IGNORE_TYPE') && $this->currentCert['tbsCertificate']['issuer'] === $this->currentCert['tbsCertificate']['subject']:
                    case defined('FILE_X509_IGNORE_TYPE') && $this->getIssuerDN(self::DN_STRING) === $this->getDN(self::DN_STRING):
                        $authorityKey = $this->getExtension('id-ce-authorityKeyIdentifier');
                        $subjectKeyID = $this->getExtension('id-ce-subjectKeyIdentifier');
                        switch (true) {
                            case !is_array($authorityKey):
                            case !$subjectKeyID:
                            case isset($authorityKey['keyIdentifier']) && $authorityKey['keyIdentifier'] === $subjectKeyID:
                                $signingCert = $this->currentCert; // working cert
                        }
                }

                if (!empty($this->CAs)) {
                    for ($i = 0; $i < count($this->CAs); $i++) {
                        // even if the cert is a self-signed one we still want to see if it's a CA;
                        // if not, we'll conditionally return an error
                        $ca = $this->CAs[$i];
                        switch (true) {
                            case !defined('FILE_X509_IGNORE_TYPE') && $this->currentCert['tbsCertificate']['issuer'] === $ca['tbsCertificate']['subject']:
                            case defined('FILE_X509_IGNORE_TYPE') && $this->getDN(self::DN_STRING, $this->currentCert['tbsCertificate']['issuer']) === $this->getDN(self::DN_STRING, $ca['tbsCertificate']['subject']):
                                $authorityKey = $this->getExtension('id-ce-authorityKeyIdentifier');
                                $subjectKeyID = $this->getExtension('id-ce-subjectKeyIdentifier', $ca);
                                switch (true) {
                                    case !is_array($authorityKey):
                                    case !$subjectKeyID:
                                    case isset($authorityKey['keyIdentifier']) && $authorityKey['keyIdentifier'] === $subjectKeyID:
                                        if (is_array($authorityKey) && isset($authorityKey['authorityCertSerialNumber']) && !$authorityKey['authorityCertSerialNumber']->equals($ca['tbsCertificate']['serialNumber'])) {
                                            break 2; // serial mismatch - check other ca
                                        }
                                        $signingCert = $ca; // working cert
                                        break 3;
                                }
                        }
                    }
                    if (count($this->CAs) == $i && $caonly) {
                        return $this->testForIntermediate($caonly, $count) && $this->validateSignature($caonly);
                    }
                } elseif (!isset($signingCert) || $caonly) {
                    return $this->testForIntermediate($caonly, $count) && $this->validateSignature($caonly);
                }
                return $this->validateSignatureHelper(
                    $signingCert['tbsCertificate']['subjectPublicKeyInfo']['algorithm']['algorithm'],
                    $signingCert['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'],
                    $this->currentCert['signatureAlgorithm']['algorithm'],
                    substr($this->currentCert['signature'], 1),
                    $this->signatureSubject
                );
            case isset($this->currentCert['certificationRequestInfo']):
                return $this->validateSignatureHelper(
                    $this->currentCert['certificationRequestInfo']['subjectPKInfo']['algorithm']['algorithm'],
                    $this->currentCert['certificationRequestInfo']['subjectPKInfo']['subjectPublicKey'],
                    $this->currentCert['signatureAlgorithm']['algorithm'],
                    substr($this->currentCert['signature'], 1),
                    $this->signatureSubject
                );
            case isset($this->currentCert['publicKeyAndChallenge']):
                return $this->validateSignatureHelper(
                    $this->currentCert['publicKeyAndChallenge']['spki']['algorithm']['algorithm'],
                    $this->currentCert['publicKeyAndChallenge']['spki']['subjectPublicKey'],
                    $this->currentCert['signatureAlgorithm']['algorithm'],
                    substr($this->currentCert['signature'], 1),
                    $this->signatureSubject
                );
            case isset($this->currentCert['tbsCertList']):
                if (!empty($this->CAs)) {
                    for ($i = 0; $i < count($this->CAs); $i++) {
                        $ca = $this->CAs[$i];
                        switch (true) {
                            case !defined('FILE_X509_IGNORE_TYPE') && $this->currentCert['tbsCertList']['issuer'] === $ca['tbsCertificate']['subject']:
                            case defined('FILE_X509_IGNORE_TYPE') && $this->getDN(self::DN_STRING, $this->currentCert['tbsCertList']['issuer']) === $this->getDN(self::DN_STRING, $ca['tbsCertificate']['subject']):
                                $authorityKey = $this->getExtension('id-ce-authorityKeyIdentifier');
                                $subjectKeyID = $this->getExtension('id-ce-subjectKeyIdentifier', $ca);
                                switch (true) {
                                    case !is_array($authorityKey):
                                    case !$subjectKeyID:
                                    case isset($authorityKey['keyIdentifier']) && $authorityKey['keyIdentifier'] === $subjectKeyID:
                                        if (is_array($authorityKey) && isset($authorityKey['authorityCertSerialNumber']) && !$authorityKey['authorityCertSerialNumber']->equals($ca['tbsCertificate']['serialNumber'])) {
                                            break 2; // serial mismatch - check other ca
                                        }
                                        $signingCert = $ca; // working cert
                                        break 3;
                                }
                        }
                    }
                }
                if (!isset($signingCert)) {
                    return false;
                }
                return $this->validateSignatureHelper(
                    $signingCert['tbsCertificate']['subjectPublicKeyInfo']['algorithm']['algorithm'],
                    $signingCert['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'],
                    $this->currentCert['signatureAlgorithm']['algorithm'],
                    substr($this->currentCert['signature'], 1),
                    $this->signatureSubject
                );
                return false;
        }
    }

    /**
     * Validates a signature
     *
     * Returns true if the signature is verified and false if it is not correct.
     * If the algorithms are unsupposed an exception is thrown.
     *
     * phpseclib 4's ASN1Signature trait has a validateSignatureHelper method but that one replaces the
     * first two parameters with an object, which works because self::$CAs is an array of X509 objects.
     * in phpseclib 3 it's $this->CAs and it's an array of arrays. we could probably still make it work
     * with X509 objects but it's more work for relatively little gain
     *
     * @throws UnsupportedAlgorithmException if the algorithm is unsupported
     */
    private function validateSignatureHelper(string $publicKeyAlgorithm, string $publicKey, string $signatureAlgorithm, string $signature, string $signatureSubject): bool
    {
        switch ($publicKeyAlgorithm) {
            case 'id-RSASSA-PSS':
                $key = RSA::loadFormat('PSS', $publicKey);
                break;
            case 'rsaEncryption':
                $key = RSA::loadFormat('PKCS8', $publicKey);
                switch ($signatureAlgorithm) {
                    case 'id-RSASSA-PSS':
                        break;
                    case 'md2WithRSAEncryption':
                    case 'md5WithRSAEncryption':
                    case 'sha1WithRSAEncryption':
                    case 'sha224WithRSAEncryption':
                    case 'sha256WithRSAEncryption':
                    case 'sha384WithRSAEncryption':
                    case 'sha512WithRSAEncryption':
                        $key = $key
                            ->withHash(preg_replace('#WithRSAEncryption$#', '', $signatureAlgorithm))
                            ->withPadding(RSA::SIGNATURE_PKCS1);
                        break;
                    default:
                        throw new UnsupportedAlgorithmException('Signature algorithm unsupported');
                }
                break;
            case 'id-Ed25519':
            case 'id-Ed448':
                $key = EC::loadFormat('PKCS8', $publicKey);
                break;
            case 'id-ecPublicKey':
                $key = EC::loadFormat('PKCS8', $publicKey);
                switch ($signatureAlgorithm) {
                    case 'ecdsa-with-SHA1':
                    case 'ecdsa-with-SHA224':
                    case 'ecdsa-with-SHA256':
                    case 'ecdsa-with-SHA384':
                    case 'ecdsa-with-SHA512':
                        $key = $key
                            ->withHash(preg_replace('#^ecdsa-with-#', '', strtolower($signatureAlgorithm)));
                        break;
                    default:
                        throw new UnsupportedAlgorithmException('Signature algorithm unsupported');
                }
                break;
            case 'id-dsa':
                $key = DSA::loadFormat('PKCS8', $publicKey);
                switch ($signatureAlgorithm) {
                    case 'id-dsa-with-sha1':
                    case 'id-dsa-with-sha224':
                    case 'id-dsa-with-sha256':
                        $key = $key
                            ->withHash(preg_replace('#^id-dsa-with-#', '', strtolower($signatureAlgorithm)));
                        break;
                    default:
                        throw new UnsupportedAlgorithmException('Signature algorithm unsupported');
                }
                break;
            default:
                throw new UnsupportedAlgorithmException('Public key algorithm unsupported');
        }

        return $key->verify($signatureSubject, $signature);
    }

    /**
     * Sets the recursion limit
     *
     * When validating a signature it may be necessary to download intermediate certs from URI's.
     * An intermediate cert that linked to itself would result in an infinite loop so to prevent
     * that we set a recursion limit. A negative number means that there is no recursion limit.
     */
    public static function setRecurLimit(int $count): void
    {
        self::$recur_limit = $count;
    }

    /**
     * Prevents URIs from being automatically retrieved
     */
    public static function disableURLFetch(): void
    {
        self::$disable_url_fetch = true;
    }

    /**
     * Allows URIs to be automatically retrieved
     */
    public static function enableURLFetch(): void
    {
        self::$disable_url_fetch = false;
    }

    /**
     * Validates an intermediate cert as identified via authority info access extension
     *
     * See https://tools.ietf.org/html/rfc4325 for more info
     */
    private function testForIntermediate(bool $caonly, int $count): bool
    {
        $opts = $this->getExtension('id-pe-authorityInfoAccess');
        if (!is_array($opts)) {
            return false;
        }
        foreach ($opts as $opt) {
            if ($opt['accessMethod'] == 'id-ad-caIssuers') {
                // accessLocation is a GeneralName. GeneralName fields support stuff like email addresses, IP addresses, LDAP,
                // etc, but we're only supporting URI's. URI's and LDAP are the only thing https://tools.ietf.org/html/rfc4325
                // discusses
                if (isset($opt['accessLocation']['uniformResourceIdentifier'])) {
                    $url = $opt['accessLocation']['uniformResourceIdentifier'];
                    break;
                }
            }
        }

        if (!isset($url)) {
            return false;
        }

        if ($count == 0) {
            self::$urlFetchDeadline = microtime(true) + self::$urlFetchTimeout;
        }
        $cert = static::fetchURL($url, self::$urlFetchDeadline);
        if (!is_string($cert)) {
            return false;
        }

        $parent = new static();
        $parent->CAs = $this->CAs;
        /*
         "Conforming applications that support HTTP or FTP for accessing
          certificates MUST be able to accept .cer files and SHOULD be able
          to accept .p7c files." -- https://tools.ietf.org/html/rfc4325

         A .p7c file is 'a "certs-only" CMS message as specified in RFC 2797"

         These are currently unsupported
        */
        if (!is_array($parent->loadX509($cert))) {
            return false;
        }
        if (!$parent->validateSignatureCountable($caonly, ++$count)) {
            return false;
        }

        $this->CAs[] = $parent->currentCert;
        //$this->loadCA($cert);

        return true;
    }

    /**
     * Fetches a URL
     *
     * If a fetch callback is set via setURLFetchCallback(), the host is resolved
     * once and the connection is pinned to that IP (the callback judges the
     * resolved IP, preventing DNS-rebinding bypass).
     */
    private static function fetchURL(string $url, ?float $deadline = null): string|false
    {
        if (self::$disable_url_fetch) {
            return false;
        }

        $method = new \ReflectionMethod(NewX509::class, 'fetchURL');
        $result = $method->invoke(null, $url, $deadline);
        return $result ?? false;
    }

    /**
     * Returns the OID corresponding to a name
     */
    public static function setURLFetchCallback(?callable $callback): void
    {
        NewX509::setURLFetchCallback(match (true) {
            $callback === null => fn () => true,
            $callback instanceof \Closure => $callback,
            default => \Closure::fromCallable($callback),
        });
        static::$urlFetchCallbackSet = true;
    }

    /**
     * Set a Distinguished Name property
     */
    public function setDNProp(string $propName, mixed $propValue, string $type = 'utf8String'): bool
    {
        if (empty($this->dn)) {
            $this->dn = ['rdnSequence' => []];
        }

        try {
            $method = new \ReflectionMethod(NewX509::class, 'translateDNProp');
            $propName = $method->invoke(null, $propName);
        } catch (\Exception) {
            return false;
        }

        foreach ((array) $propValue as $v) {
            if (!is_array($v) && isset($type)) {
                $v = [$type => $v];
            }
            $this->dn['rdnSequence'][] = [
                [
                    'type' => $propName,
                    'value' => $v
                ]
            ];
        }

        return true;
    }

    /**
     * Remove Distinguished Name properties
     */
    public function removeDNProp(string $propName): void
    {
        if (empty($this->dn)) {
            return;
        }

        try {
            $method = new \ReflectionMethod(NewX509::class, 'translateDNProp');
            $propName = $method->invoke(null, $propName);
        } catch (\Exception) {
            return;
        }

        $dn = &$this->dn['rdnSequence'];
        $size = count($dn);
        for ($i = 0; $i < $size; $i++) {
            if ($dn[$i][0]['type'] == $propName) {
                unset($dn[$i]);
            }
        }

        $dn = array_values($dn);
    }

    /**
     * Set a Distinguished Name
     */
    public function setDN(array|string $dn, bool $merge = false, string $type = 'utf8String'): bool
    {
        if (!$merge) {
            $this->dn = null;
        }

        if (is_array($dn)) {
            if (isset($dn['rdnSequence'])) {
                $this->dn = $dn; // No merge here.
                return true;
            }

            // handles stuff generated by openssl_x509_parse()
            foreach ($dn as $prop => $value) {
                if (!$this->setDNProp($prop, $value, $type)) {
                    return false;
                }
            }
            return true;
        }

        // handles everything else
        $results = preg_split('#((?:^|, *|/)(?:C=|O=|OU=|CN=|L=|ST=|SN=|postalCode=|streetAddress=|emailAddress=|serialNumber=|organizationalUnitName=|title=|description=|role=|x500UniqueIdentifier=|postalAddress=))#', $dn, -1, PREG_SPLIT_DELIM_CAPTURE);
        for ($i = 1; $i < count($results); $i += 2) {
            $prop = trim($results[$i], ', =/');
            $value = $results[$i + 1];
            if (!$this->setDNProp($prop, $value, $type)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Set public key
     */
    public function setPublicKey(PublicKey $key): void
    {
        $this->publicKey = $key;
    }

    /**
     * Set private key
     */
    public function setPrivateKey(PrivateKey $key): void
    {
        $this->privateKey = $key;
    }

    /**
     * Set challenge
     *
     * Used for SPKAC CSR's
     */
    public function setChallenge(string $challenge): void
    {
        $this->challenge = $challenge;
    }

    /**
     * Turns the certificate into a certificate authority
     */
    public function makeCA()
    {
        $this->caFlag = true;
    }

    /**
     * Helper function to build domain array
     */
    private static function dnsName(string $domain): array
    {
        return ['dNSName' => $domain];
    }

    /**
     * Set the IP Addresses's which the cert is to be valid for
     */
    public function setIPAddress(string ...$ipAddresses): void
    {
        $this->ipAddresses = $ipAddresses;
        /*
        if (!isset($this->domains)) {
            $this->removeDNProp('id-at-commonName');
            $this->setDNProp('id-at-commonName', $this->ipAddresses[0]);
        }
        */
    }

    /**
     * Set the domain name's which the cert is to be valid for
     */
    public function setDomain(string ...$domains): void
    {
        $this->domains = $domains;
        $this->removeDNProp('id-at-commonName');
        $this->setDNProp('id-at-commonName', $this->domains[0]);
    }

    /**
     * Format a public key as appropriate
     */
    private function formatSubjectPublicKey(): array|false
    {
        $format = $this->publicKey instanceof RSA && ($this->publicKey->getPadding() & RSA::SIGNATURE_PSS) ?
            'PSS' :
            'PKCS8';

        $publicKey = base64_decode(preg_replace('#-.+-|[\r\n]#', '', $this->publicKey->toString($format)));

        try {
            $decoded = NewASN1::decodeBER($publicKey);
            $mapped = NewASN1::map($decoded, Maps\SubjectPublicKeyInfo::MAP)->toArray();
        } catch (\Exception $e) {
            return false;
        }

        $mapped['subjectPublicKey'] = $this->publicKey->toString($format);

        return $mapped;
    }

    /**
     * Helper function to build a time field according to RFC 3280 section
     *  - 4.1.2.5 Validity
     *  - 5.1.2.4 This Update
     *  - 5.1.2.5 Next Update
     *  - 5.1.2.6 Revoked Certificates
     * by choosing utcTime iff year of date given is before 2050 and generalTime else.
     */
    private function timeField(string|Element $date): array|Element
    {
        if ($date instanceof Element) {
            return $date;
        }
        $dateObj = new \DateTimeImmutable($date, new \DateTimeZone('GMT'));
        $year = $dateObj->format('Y'); // the same way ASN1.php parses this
        if ($year < 2050) {
            return ['utcTime' => $date];
        } else {
            return ['generalTime' => $date];
        }
    }

    /**
     * Get a CSR attribute
     *
     * Returns the attribute if it exists and false if not
     */
    public function getAttribute(string $id, int $disposition = self::ATTR_ALL, ?array $csr = null): bool|array|string
    {
        if (empty($csr)) {
            $csr = $this->currentCert;
        }

        $attributes = Arrays::subArray($csr, 'certificationRequestInfo/attributes');

        if (!is_array($attributes)) {
            return false;
        }

        foreach ($attributes as $key => $attribute) {
            if ($attribute['type'] == $id) {
                $n = count($attribute['value']);
                switch (true) {
                    case $disposition == self::ATTR_APPEND:
                    case $disposition == self::ATTR_REPLACE:
                        return false;
                    case $disposition == self::ATTR_ALL:
                        return $attribute['value'];
                    case $disposition >= $n:
                        $disposition -= $n;
                        break;
                    default:
                        return $attribute['value'][$disposition];
                }
            }
        }

        return false;
    }

    /**
     * Remove a certificate, CSR or CRL Extension
     */
    public function removeExtension(string $id): bool
    {
        return $this->removeExtensionHelper($id);
    }

    /**
     * Remove an Extension
     */
    private function removeExtensionHelper(string $id, ?string $path = null): bool
    {
        $extensions = &$this->extensions($this->currentCert, $path);

        if (!is_array($extensions)) {
            return false;
        }

        $result = false;
        foreach ($extensions as $key => $value) {
            if ($value['extnId'] == $id) {
                unset($extensions[$key]);
                $result = true;
            }
        }

        //return array_values($extensions);

        return true;
    }

    /**
     * Set a certificate, CSR or CRL Extension
     */
    public function setExtension(string $id, array|string|int $value, bool $critical = false, bool $replace = true): bool
    {
        return $this->setExtensionHelper($id, $value, $critical, $replace);
    }

    /**
     * Register the mapping for a custom/unsupported extension.
     */
    public function setExtensionValue(string $id, mixed $value, bool $critical = false, bool $replace = false): void
    {
        $this->extensionValues[$id] = compact('critical', 'replace', 'value');
    }

    /**
     * Set an Extension
     */
    private function setExtensionHelper(string $id, array|string|int $value, bool $critical = false, bool $replace = true, ?string $path = null): bool
    {
        $extensions = &$this->extensions($this->currentCert, $path, true);

        if (!is_array($extensions)) {
            return false;
        }

        $newext = ['extnId'  => $id, 'critical' => $critical, 'extnValue' => $value];

        foreach ($extensions as $key => $value) {
            if ($value['extnId'] == $id) {
                if (!$replace) {
                    return false;
                }

                $extensions[$key] = $newext;
                return true;
            }
        }

        $extensions[] = $newext;
        return true;
    }

    /**
     * Compute a public key identifier.
     *
     * Although key identifiers may be set to any unique value, this function
     * computes key identifiers from public key according to the two
     * recommended methods (4.2.1.2 RFC 3280).
     * Highly polymorphic: try to accept all possible forms of key:
     * - Key object
     * - \phpseclib3\File\X509 object with public or private key defined
     * - Certificate or CSR array
     * - \phpseclib3\File\ASN1\Element object
     * - PEM or DER string
     */
    public function computeKeyIdentifier(X509|Element|array|string|null $key = null, int $method = 1): string
    {
        if (is_null($key)) {
            $key = $this;
        }

        switch (true) {
            case is_string($key):
                break;
            case is_array($key) && isset($key['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey']):
                return $this->computeKeyIdentifier($key['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'], $method);
            case is_array($key) && isset($key['certificationRequestInfo']['subjectPKInfo']['subjectPublicKey']):
                return $this->computeKeyIdentifier($key['certificationRequestInfo']['subjectPKInfo']['subjectPublicKey'], $method);
            case !is_object($key):
                return false;
            case $key instanceof Element:
                // Assume the element is a bitstring-packed key.
                try {
                    $decoded = NewASN1::decodeBER($key->element);
                    $raw = NewASN1::map($decoded, ['type' => NewASN1::TYPE_BIT_STRING])->value;
                } catch (\Exception $e) {
                    return false;
                }
                if (empty($raw)) {
                    return false;
                }
                // If the key is private, compute identifier from its corresponding public key.
                $key = PublicKeyLoader::load($raw);
                if ($key instanceof PrivateKey) {  // If private.
                    return $this->computeKeyIdentifier($key, $method);
                }
                $key = $raw; // Is a public key.
                break;
            case $key instanceof X509:
                if (isset($key->publicKey)) {
                    return $this->computeKeyIdentifier($key->publicKey, $method);
                }
                if (isset($key->privateKey)) {
                    return $this->computeKeyIdentifier($key->privateKey, $method);
                }
                if (isset($key->currentCert['tbsCertificate']) || isset($key->currentCert['certificationRequestInfo'])) {
                    return $this->computeKeyIdentifier($key->currentCert, $method);
                }
                return false;
            default: // Should be a key object (i.e.: \phpseclib3\Crypt\RSA).
                $key = $key->getPublicKey();
                break;
        }

        // If in PEM format, convert to binary.
        $key = NewASN1::extractBER($key);

        // Now we have the key string: compute its sha-1 sum.
        $hash = new Hash('sha1');
        $hash = $hash->hash($key);

        if ($method == 2) {
            $hash = substr($hash, -8);
            $hash[0] = chr((ord($hash[0]) & 0x0F) | 0x40);
        }

        return $hash;
    }

    /**
     * Register the mapping for a custom/unsupported extension.
     */
    public static function registerExtension(string $id, array $mapping): void
    {
        $method = new \ReflectionMethod(NewX509::class, 'getMapping');
        $oldMapping = $method->invoke(null, $id);
        if (isset($oldMapping) && $oldMapping === $mapping) {
            return;
        }
        try {
            NewX509::registerExtension($id, $mapping);
        } catch (InvalidStateException $e) {
            throw new \RuntimeException($e->getMessage());
        }
    }

    /**
     * Register the mapping for a custom/unsupported extension.
     */
    public static function getRegisteredExtension(string $id): ?array
    {
        return NewX509::getRegisteredExtension($id);
    }

    /**
     * Returns the current cert
     */
    public function &getCurrentCert(): bool|array|null
    {
        return $this->currentCert;
    }

    /**
     * Get the certificate chain for the current cert
     */
    public function getChain(): bool|array
    {
        $chain = [$this->currentCert];

        if (!is_array($this->currentCert) || !isset($this->currentCert['tbsCertificate'])) {
            return false;
        }
        while (true) {
            $currentCert = $chain[count($chain) - 1];
            for ($i = 0; $i < count($this->CAs); $i++) {
                $ca = $this->CAs[$i];
                if ($currentCert['tbsCertificate']['issuer'] === $ca['tbsCertificate']['subject']) {
                    $authorityKey = $this->getExtension('id-ce-authorityKeyIdentifier', $currentCert);
                    $subjectKeyID = $this->getExtension('id-ce-subjectKeyIdentifier', $ca);
                    switch (true) {
                        case !is_array($authorityKey):
                        case is_array($authorityKey) && isset($authorityKey['keyIdentifier']) && $authorityKey['keyIdentifier'] === $subjectKeyID:
                            if ($currentCert === $ca) {
                                break 3;
                            }
                            $chain[] = $ca;
                            break 2;
                    }
                }
            }
            if ($i == count($this->CAs)) {
                break;
            }
        }
        foreach ($chain as $key => $value) {
            $chain[$key] = new X509();
            $chain[$key]->loadX509($value);
        }
        return $chain;
    }

    /**
     * Sets the subject key identifier
     *
     * This is used by the id-ce-authorityKeyIdentifier and the id-ce-subjectKeyIdentifier extensions.
     */
    public function setKeyIdentifier(string $value): void
    {
        if (empty($value)) {
            unset($this->currentKeyIdentifier);
        } else {
            $this->currentKeyIdentifier = $value;
        }
    }

    /**
     * Set Serial Number
     */
    public function setSerialNumber(string $serial, int $base = -256): void
    {
        $this->serialNumber = new BigInteger($serial, $base);
    }

    /**
     * Set certificate start date
     */
    public function setStartDate(\DateTimeInterface|string $date): void
    {
        if (is_string($date)) {
            $date = new \DateTimeImmutable($date, new \DateTimeZone(@date_default_timezone_get()));
        }

        $this->startDate = $date->format('D, d M Y H:i:s O');
    }

    /**
     * Set certificate end date
     */
    public function setEndDate(\DateTimeInterface|string $date): void
    {
        /*
          To indicate that a certificate has no well-defined expiration date,
          the notAfter SHOULD be assigned the GeneralizedTime value of
          99991231235959Z.

          -- http://tools.ietf.org/html/rfc5280#section-4.1.2.5
        */
        if (is_string($date) && strtolower($date) === 'lifetime') {
            $temp = '99991231235959Z';
            $temp = chr(ASN1::TYPE_GENERALIZED_TIME) . ASN1::encodeLength(strlen($temp)) . $temp;
            $this->endDate = new Element($temp);
        } else {
            if (is_string($date)) {
                $date = new \DateTimeImmutable($date, new \DateTimeZone(@date_default_timezone_get()));
            }

            $this->endDate = $date->format('D, d M Y H:i:s O');
        }
    }

    /**
     * Sign an X.509 certificate
     *
     * $issuer's private key needs to be loaded.
     * $subject can be either an existing X.509 cert (if you want to resign it),
     * a CSR or something with the DN and public key explicitly set.
     */
    public function sign(X509 $issuer, X509 $subject): bool|array
    {
        if (!is_object($issuer->privateKey) || empty($issuer->dn)) {
            return false;
        }

        if (isset($subject->publicKey) && !($subjectPublicKey = $subject->formatSubjectPublicKey())) {
            return false;
        }

        $currentCert = $this->currentCert ?? null;
        $signatureSubject = $this->signatureSubject ?? null;

        $reflection = new \ReflectionProperty($issuer->privateKey, 'key');
        $v4Key = $reflection->getValue($issuer->privateKey);

        try {
            $signatureAlgorithm = self::identifySignatureAlgorithmHelper($v4Key);
        } catch (NewUnsupportedAlgorithmException $e) {
            throw new UnsupportedAlgorithmException($e->getMessage());
        }

        if (isset($subject->currentCert) && is_array($subject->currentCert) && isset($subject->currentCert['tbsCertificate'])) {
            $this->currentCert = $subject->currentCert;
            $this->currentCert['tbsCertificate']['signature'] = $signatureAlgorithm;
            $this->currentCert['signatureAlgorithm'] = $signatureAlgorithm;

            if (!empty($this->startDate)) {
                $this->currentCert['tbsCertificate']['validity']['notBefore'] = $this->timeField($this->startDate);
            }
            if (!empty($this->endDate)) {
                $this->currentCert['tbsCertificate']['validity']['notAfter'] = $this->timeField($this->endDate);
            }
            if (!empty($this->serialNumber)) {
                $this->currentCert['tbsCertificate']['serialNumber'] = $this->serialNumber;
            }
            if (!empty($subject->dn)) {
                $this->currentCert['tbsCertificate']['subject'] = $subject->dn;
            }
            if (!empty($subject->publicKey)) {
                $this->currentCert['tbsCertificate']['subjectPublicKeyInfo'] = $subjectPublicKey;
            }
            $this->removeExtension('id-ce-authorityKeyIdentifier');
            if (isset($subject->domains)) {
                $this->removeExtension('id-ce-subjectAltName');
            }
        } elseif (isset($subject->currentCert) && is_array($subject->currentCert) && isset($subject->currentCert['tbsCertList'])) {
            return false;
        } else {
            if (!isset($subject->publicKey)) {
                return false;
            }

            $startDate = new \DateTimeImmutable('now', new \DateTimeZone(@date_default_timezone_get()));
            $startDate = !empty($this->startDate) ? $this->startDate : $startDate->format('D, d M Y H:i:s O');

            $endDate = new \DateTimeImmutable('+1 year', new \DateTimeZone(@date_default_timezone_get()));
            $endDate = !empty($this->endDate) ? $this->endDate : $endDate->format('D, d M Y H:i:s O');

            /* "The serial number MUST be a positive integer"
               "Conforming CAs MUST NOT use serialNumber values longer than 20 octets."
                -- https://tools.ietf.org/html/rfc5280#section-4.1.2.2

               for the integer to be positive the leading bit needs to be 0 hence the
               application of a bitmap
            */
            $serialNumber = !empty($this->serialNumber) ?
                $this->serialNumber :
                new BigInteger(random_bytes(20) & ("\x7F" . str_repeat("\xFF", 19)), 256);

            $this->currentCert = [
                'tbsCertificate' =>
                    [
                        'version' => 'v3',
                        'serialNumber' => $serialNumber, // $this->setSerialNumber()
                        'signature' => $signatureAlgorithm,
                        'issuer' => false, // this is going to be overwritten later
                        'validity' => [
                            'notBefore' => $this->timeField($startDate), // $this->setStartDate()
                            'notAfter' => $this->timeField($endDate)   // $this->setEndDate()
                        ],
                        'subject' => $subject->dn,
                        'subjectPublicKeyInfo' => $subjectPublicKey
                    ],
                'signatureAlgorithm' => $signatureAlgorithm,
                'signature'          => '' // this is going to be overwritten later
            ];

            // Copy extensions from CSR.
            $csrexts = $subject->getAttribute('pkcs-9-at-extensionRequest', 0);

            if (!empty($csrexts)) {
                $this->currentCert['tbsCertificate']['extensions'] = $csrexts;
            }
        }

        $this->currentCert['tbsCertificate']['issuer'] = $issuer->dn;

        if (isset($issuer->currentKeyIdentifier)) {
            $this->setExtension('id-ce-authorityKeyIdentifier', [
                //'authorityCertIssuer' => array(
                //    array(
                //        'directoryName' => $issuer->dn
                //    )
                //),
                'keyIdentifier' => $issuer->currentKeyIdentifier
            ]);
            //$extensions = &$this->currentCert['tbsCertificate']['extensions'];
            //if (isset($issuer->serialNumber)) {
            //    $extensions[count($extensions) - 1]['authorityCertSerialNumber'] = $issuer->serialNumber;
            //}
            //unset($extensions);
        }

        if (isset($subject->currentKeyIdentifier)) {
            $this->setExtension('id-ce-subjectKeyIdentifier', $subject->currentKeyIdentifier);
        }

        $altName = [];

        if (isset($subject->domains) && count($subject->domains)) {
            $altName = array_map(['\phpseclib3\File\X509', 'dnsName'], $subject->domains);
        }

        if (isset($subject->ipAddresses) && count($subject->ipAddresses)) {
            // should an IP address appear as the CN if no domain name is specified? idk
            //$ips = count($subject->domains) ? $subject->ipAddresses : array_slice($subject->ipAddresses, 1);
            $ipAddresses = [];
            foreach ($subject->ipAddresses as $ipAddress) {
                $encoded = $subject->ipAddress($ipAddress);
                if ($encoded !== false) {
                    $ipAddresses[] = $encoded;
                }
            }
            if (count($ipAddresses)) {
                $altName = array_merge($altName, $ipAddresses);
            }
        }

        if (!empty($altName)) {
            $this->setExtension('id-ce-subjectAltName', $altName);
        }

        if ($this->caFlag) {
            $keyUsage = $this->getExtension('id-ce-keyUsage');
            if (!$keyUsage) {
                $keyUsage = [];
            }

            $this->setExtension(
                'id-ce-keyUsage',
                array_values(array_unique(array_merge($keyUsage, ['cRLSign', 'keyCertSign'])))
            );

            $basicConstraints = $this->getExtension('id-ce-basicConstraints');
            if (!$basicConstraints) {
                $basicConstraints = [];
            }

            $this->setExtension(
                'id-ce-basicConstraints',
                array_merge(['cA' => true], $basicConstraints),
                true
            );

            if (!isset($subject->currentKeyIdentifier)) {
                $this->setExtension('id-ce-subjectKeyIdentifier', $this->computeKeyIdentifier($this->currentCert), false, false);
            }
        }

        // resync $this->signatureSubject
        // save $tbsCertificate in case there are any \phpseclib3\File\ASN1\Element objects in it
        $tbsCertificate = $this->currentCert['tbsCertificate'];
        $this->loadX509($this->saveX509($this->currentCert));

        $result = $this->currentCert;
        $this->currentCert['signature'] = $result['signature'] = "\0" . $issuer->privateKey->sign($this->signatureSubject);
        $result['tbsCertificate'] = $tbsCertificate;

        $this->currentCert = $currentCert;
        $this->signatureSubject = $signatureSubject;

        return $result;
    }

    /**
     * Load a SPKAC CSR
     *
     * SPKAC's are produced by the HTML5 keygen element:
     *
     * https://developer.mozilla.org/en-US/docs/HTML/Element/keygen
     */
    public function loadSPKAC(string|array $spkac): bool|array
    {
        if (is_array($spkac) && isset($spkac['publicKeyAndChallenge'])) {
            unset($this->currentCert);
            unset($this->currentKeyIdentifier);
            unset($this->signatureSubject);
            $this->currentCert = $spkac;
            return $spkac;
        }

        try {
            $constructed = SPKAC::load($spkac);
            $this->signatureSubject = $constructed['publicKeyAndChallenge']->getEncoded();
            $this->currentCert = $constructed->toArray();
        } catch (\Exception $e) {
            unset($this->currentCert, $this->signatureSubject);
            return false;
        }

        $this->convertPublicKey('publicKeyAndChallenge/spki', $constructed);
        array_walk_recursive($this->currentCert, self::map(...));
        Arrays::subArrayMapWithWildcards($this->currentCert, 'publicKeyAndChallenge/challenge', fn ($val) => $val['ia5String']);
        $this->publicKey = $this->getPublicKey();

        return $this->currentCert;
    }

    /**
     * Sign a SPKAC
     */
    public function signSPKAC(): bool|array
    {
        if (!is_object($this->privateKey)) {
            return false;
        }

        $origPublicKey = $this->publicKey;
        $this->publicKey = $this->privateKey->getPublicKey();
        $publicKey = $this->formatSubjectPublicKey();
        $this->publicKey = $origPublicKey;

        $currentCert = $this->currentCert ?? null;
        $signatureSubject = $this->signatureSubject ?? null;

        $reflection = new \ReflectionProperty($this->privateKey, 'key');
        $v4Key = $reflection->getValue($this->privateKey);

        try {
            $signatureAlgorithm = self::identifySignatureAlgorithmHelper($v4Key);
        } catch (NewUnsupportedAlgorithmException $e) {
            throw new UnsupportedAlgorithmException($e->getMessage());
        }

        // re-signing a SPKAC seems silly but since everything else supports re-signing why not?
        if (isset($this->currentCert) && is_array($this->currentCert) && isset($this->currentCert['publicKeyAndChallenge'])) {
            $this->currentCert['signatureAlgorithm'] = $signatureAlgorithm;
            $this->currentCert['publicKeyAndChallenge']['spki'] = $publicKey;
            if (!empty($this->challenge)) {
                // the bitwise AND ensures that the output is a valid IA5String
                $this->currentCert['publicKeyAndChallenge']['challenge'] = $this->challenge & str_repeat("\x7F", strlen($this->challenge));
            }
        } else {
            $this->currentCert = [
                'publicKeyAndChallenge' =>
                    [
                        'spki' => $publicKey,
                        // quoting <https://developer.mozilla.org/en-US/docs/Web/HTML/Element/keygen>,
                        // "A challenge string that is submitted along with the public key. Defaults to an empty string if not specified."
                        // both Firefox and OpenSSL ("openssl spkac -key private.key") behave this way
                        // we could alternatively do this instead if we ignored the specs:
                        // Random::string(8) & str_repeat("\x7F", 8)
                        'challenge' => !empty($this->challenge) ? $this->challenge : ''
                    ],
                'signatureAlgorithm' => $signatureAlgorithm,
                'signature'          => '' // this is going to be overwritten later
            ];
        }

        // resync $this->signatureSubject
        // save $publicKeyAndChallenge in case there are any \phpseclib3\File\ASN1\Element objects in it
        $publicKeyAndChallenge = $this->currentCert['publicKeyAndChallenge'];
        $this->loadSPKAC($this->saveSPKAC($this->currentCert));

        $result = $this->currentCert;
        $this->currentCert['signature'] = $result['signature'] = "\0" . $this->privateKey->sign($this->signatureSubject);
        $result['publicKeyAndChallenge'] = $publicKeyAndChallenge;

        $this->currentCert = $currentCert;
        $this->signatureSubject = $signatureSubject;

        return $result;
    }

    /**
     * Save a SPKAC CSR request
     */
    public function saveSPKAC(array $spkac, int $format = self::FORMAT_PEM): bool|string
    {
        if (!isset($spkac['publicKeyAndChallenge'])) {
            return false;
        }

        $spkac = self::convertToV4($spkac);

        $spkac['publicKeyAndChallenge']['spki'] = new NewElement(
            base64_decode(preg_replace('#-.+-|[\r\n]#', '', $spkac['publicKeyAndChallenge']['spki']['subjectPublicKey']))
        );

        $writer = new SPKAC();
        $ref = new \ReflectionObject($writer);
        $prop = $ref->getProperty('spkac');
        $prop->setValue($writer, $spkac);

        return $writer->toString(['binary' => $format === self::FORMAT_DER]);
    }

    /**
     * Load a Certificate Signing Request
     */
    public function loadCSR(string|array $csr, int $mode = self::FORMAT_AUTO_DETECT): bool|array
    {
        if (is_array($csr)) {
            unset($this->currentCert);
            unset($this->currentKeyIdentifier);
            unset($this->signatureSubject);
            $this->dn = $csr['certificationRequestInfo']['subject'];
            if (!isset($this->dn)) {
                return false;
            }

            $this->currentCert = $csr;
            return $csr;
        }

        $constructed = CSR::load($csr, $mode);
        try {
            $this->signatureSubject = $constructed['certificationRequestInfo']->getEncoded();
            $this->currentCert = $constructed->toArray();
        } catch (\Exception $e) {
            unset($this->currentCert);
            return false;
        }

        $this->convertPublicKey('certificationRequestInfo/subjectPKInfo', $constructed);

        array_walk_recursive($this->currentCert, self::map(...));
        self::convertDNtoPostV3($this->currentCert['certificationRequestInfo']['subject']['rdnSequence']);

        $this->dn = $this->currentCert['certificationRequestInfo']['subject'];

        //$this->publicKey = $this->getPublicKey();

        return $this->currentCert;
    }

    /**
     * Save CSR request
     */
    public function saveCSR(array $csr, int $format = self::FORMAT_PEM): string|bool
    {
        if (!isset($csr['certificationRequestInfo'])) {
            return false;
        }

        self::convertDNtoPreV4($csr['certificationRequestInfo']['subject']);
        $csr = self::convertToV4($csr);

        $csr['certificationRequestInfo']['subjectPKInfo'] = new NewElement(
            base64_decode(preg_replace('#-.+-|[\r\n]#', '', $csr['certificationRequestInfo']['subjectPKInfo']['subjectPublicKey']))
        );

        $writer = new CSR();
        $ref = new \ReflectionObject($writer);
        $prop = $ref->getProperty('csr');
        $prop->setValue($writer, $csr);
        return $writer->toString(['binary' => $format === self::FORMAT_DER]);
    }

    /**
     * Sign a CSR
     */
    public function signCSR(): bool|array
    {
        if (!is_object($this->privateKey) || empty($this->dn)) {
            return false;
        }

        $origPublicKey = $this->publicKey;
        $this->publicKey = $this->privateKey->getPublicKey();
        $publicKey = $this->formatSubjectPublicKey();
        $this->publicKey = $origPublicKey;

        $currentCert = $this->currentCert ?? null;
        $signatureSubject = $this->signatureSubject ?? null;

        $reflection = new \ReflectionProperty($this->privateKey, 'key');
        $v4Key = $reflection->getValue($this->privateKey);

        try {
            $signatureAlgorithm = self::identifySignatureAlgorithmHelper($v4Key);
        } catch (NewUnsupportedAlgorithmException $e) {
            throw new UnsupportedAlgorithmException($e->getMessage());
        }

        if (isset($this->currentCert) && is_array($this->currentCert) && isset($this->currentCert['certificationRequestInfo'])) {
            $this->currentCert['signatureAlgorithm'] = $signatureAlgorithm;
            if (!empty($this->dn)) {
                $this->currentCert['certificationRequestInfo']['subject'] = $this->dn;
            }
            $this->currentCert['certificationRequestInfo']['subjectPKInfo'] = $publicKey;
        } else {
            $this->currentCert = [
                'certificationRequestInfo' =>
                    [
                        'version' => 'v1',
                        'subject' => $this->dn,
                        'subjectPKInfo' => $publicKey,
                        'attributes' => []
                    ],
                'signatureAlgorithm' => $signatureAlgorithm,
                'signature'          => '' // this is going to be overwritten later
            ];
        }

        // resync $this->signatureSubject
        // save $certificationRequestInfo in case there are any \phpseclib3\File\ASN1\Element objects in it
        $certificationRequestInfo = $this->currentCert['certificationRequestInfo'];
        $this->loadCSR($this->saveCSR($this->currentCert));

        $result = $this->currentCert;
        $this->currentCert['signature'] = $result['signature'] = "\0" . $this->privateKey->sign($this->signatureSubject);
        $result['certificationRequestInfo'] = $certificationRequestInfo;

        $this->currentCert = $currentCert;
        $this->signatureSubject = $signatureSubject;

        return $result;
    }

    /**
     * Set a CSR attribute
     */
    public function setAttribute(string $id, mixed $value, int $disposition = self::ATTR_ALL): bool
    {
        $attributes = &Arrays::subArray($this->currentCert, 'certificationRequestInfo/attributes', true);

        if (!is_array($attributes)) {
            return false;
        }

        switch ($disposition) {
            case self::ATTR_REPLACE:
                $disposition = self::ATTR_APPEND;
            // fall-through
            case self::ATTR_ALL:
                $this->removeAttribute($id);
                break;
        }

        foreach ($attributes as $key => $attribute) {
            if ($attribute['type'] == $id) {
                $n = count($attribute['value']);
                switch (true) {
                    case $disposition == self::ATTR_APPEND:
                        $last = $key;
                        break;
                    case $disposition >= $n:
                        $disposition -= $n;
                        break;
                    default:
                        $attributes[$key]['value'][$disposition] = $value;
                        return true;
                }
            }
        }

        switch (true) {
            case $disposition >= 0:
                return false;
            case isset($last):
                $attributes[$last]['value'][] = $value;
                break;
            default:
                $attributes[] = ['type' => $id, 'value' => $disposition == self::ATTR_ALL ? $value : [$value]];
                break;
        }

        return true;
    }

    /**
     * Load a Certificate Revocation List
     */
    public function loadCRL(string|array $crl, int $mode = self::FORMAT_AUTO_DETECT): bool|array
    {
        if (is_array($crl)) {
            $this->currentCert = $crl;
            unset($this->signatureSubject);
            return $crl;
        }
        $crl = CRL::load($crl, $mode);
        $this->signatureSubject = $crl['tbsCertList']->getEncoded();
        try {
            $revoked = [];
            $list = &$crl['tbsCertList']['revokedCertificates'];
            $total = count($list);
            for ($i = 0; $i < $total; $i++) {
                $temp = [];
                $temp['userCertificate'] = new BigInteger((string) $list[$i]['userCertificate']);
                $temp['revocationDate'][$list[$i]['revocationDate']->index] = $list[$i]['revocationDate']->value->format(ASN1::$format);
                if (isset($list[$i]['crlEntryExtensions'])) {
                    $exts = &$list[$i]['crlEntryExtensions'];
                    $totalExts = count($exts);
                    for ($j = 0; $j < $totalExts; $j++) {
                        $temp['crlEntryExtensions'][] = [
                            'extnId' => (string) $exts[$j]['extnId'],
                            'critical' => $exts[$j]['critical']->value,
                            'extnValue' => $exts[$j]['extnValue'] instanceof Constructed ?
                                $exts[$j]['extnValue']->toArray() :
                                $exts[$j]['extnValue'],
                        ];
                    }
                }
                unset($list[$i]);
                array_walk_recursive($temp, self::map(...));
                $revoked[] = $temp;
            }
            unset($crl['tbsCertList']['revokedCertificates']);
            $this->currentCert = $crl->toArray();
            array_walk_recursive($this->currentCert, self::map(...));
            self::convertDNtoPostV3($this->currentCert['tbsCertList']['issuer']['rdnSequence']);
            $this->currentCert['tbsCertList']['revokedCertificates'] = $revoked;
            return $this->currentCert;
        } catch (\Exception $e) {
            unset($this->currentCert);
            return false;
        }
    }

    /**
     * Save Certificate Revocation List.
     */
    public function saveCRL(array $crl, int $format = self::FORMAT_PEM): string
    {
        if (!is_array($crl) || !isset($crl['tbsCertList'])) {
            return false;
        }

        $crl = self::convertToV4($crl);

        $writer = new CRL();
        $ref = new \ReflectionObject($writer);
        $prop = $ref->getProperty('crl');
        $prop->setValue($writer, $crl);
        return $writer->toString(['binary' => $format === self::FORMAT_DER]);
    }

    /**
     * Sign a CRL
     *
     * $issuer's private key needs to be loaded.
     */
    public function signCRL(X509 $issuer, X509 $crl): array|false
    {
        if (!is_object($issuer->privateKey) || empty($issuer->dn)) {
            return false;
        }

        $currentCert = $this->currentCert ?? null;
        $signatureSubject = $this->signatureSubject ?? null;

        $reflection = new \ReflectionProperty($issuer->privateKey, 'key');
        $v4Key = $reflection->getValue($issuer->privateKey);

        try {
            $signatureAlgorithm = self::identifySignatureAlgorithmHelper($v4Key);
        } catch (NewUnsupportedAlgorithmException $e) {
            throw new UnsupportedAlgorithmException($e->getMessage());
        }

        $thisUpdate = new \DateTimeImmutable('now', new \DateTimeZone(@date_default_timezone_get()));
        $thisUpdate = !empty($this->startDate) ? $this->startDate : $thisUpdate->format('D, d M Y H:i:s O');

        if (isset($crl->currentCert) && is_array($crl->currentCert) && isset($crl->currentCert['tbsCertList'])) {
            $this->currentCert = $crl->currentCert;
            $this->currentCert['tbsCertList']['signature'] = $signatureAlgorithm;
            $this->currentCert['signatureAlgorithm'] = $signatureAlgorithm;
        } else {
            $this->currentCert = [
                'tbsCertList' =>
                    [
                        'version' => 'v2',
                        'signature' => $signatureAlgorithm,
                        'issuer' => false, // this is going to be overwritten later
                        'thisUpdate' => $this->timeField($thisUpdate) // $this->setStartDate()
                    ],
                'signatureAlgorithm' => $signatureAlgorithm,
                'signature'          => '' // this is going to be overwritten later
            ];
        }

        $tbsCertList = &$this->currentCert['tbsCertList'];
        $tbsCertList['issuer'] = $issuer->dn;
        $tbsCertList['thisUpdate'] = $this->timeField($thisUpdate);

        if (!empty($this->endDate)) {
            $tbsCertList['nextUpdate'] = $this->timeField($this->endDate); // $this->setEndDate()
        } else {
            unset($tbsCertList['nextUpdate']);
        }

        if (!empty($this->serialNumber)) {
            $crlNumber = $this->serialNumber;
        } else {
            $crlNumber = $this->getExtension('id-ce-cRLNumber');
            // "The CRL number is a non-critical CRL extension that conveys a
            //  monotonically increasing sequence number for a given CRL scope and
            //  CRL issuer.  This extension allows users to easily determine when a
            //  particular CRL supersedes another CRL."
            // -- https://tools.ietf.org/html/rfc5280#section-5.2.3
            $crlNumber = $crlNumber !== false ? $crlNumber->add(new BigInteger(1)) : null;
        }

        $this->removeExtension('id-ce-authorityKeyIdentifier');
        $this->removeExtension('id-ce-issuerAltName');

        // Be sure version >= v2 if some extension found.
        $version = isset($tbsCertList['version']) ? $tbsCertList['version'] : 0;
        if (!$version) {
            if (!empty($tbsCertList['crlExtensions'])) {
                $version = 'v2'; // v2.
            } elseif (!empty($tbsCertList['revokedCertificates'])) {
                foreach ($tbsCertList['revokedCertificates'] as $cert) {
                    if (!empty($cert['crlEntryExtensions'])) {
                        $version = 'v2'; // v2.
                    }
                }
            }

            if ($version) {
                $tbsCertList['version'] = $version;
            }
        }

        // Store additional extensions.
        if (!empty($tbsCertList['version'])) { // At least v2.
            if (!empty($crlNumber)) {
                $this->setExtension('id-ce-cRLNumber', $crlNumber);
            }

            if (isset($issuer->currentKeyIdentifier)) {
                $this->setExtension('id-ce-authorityKeyIdentifier', [
                    //'authorityCertIssuer' => array(
                    //    ]
                    //        'directoryName' => $issuer->dn
                    //    ]
                    //),
                    'keyIdentifier' => $issuer->currentKeyIdentifier
                ]);
                //$extensions = &$tbsCertList['crlExtensions'];
                //if (isset($issuer->serialNumber)) {
                //    $extensions[count($extensions) - 1]['authorityCertSerialNumber'] = $issuer->serialNumber;
                //}
                //unset($extensions);
            }

            $issuerAltName = $this->getExtension('id-ce-subjectAltName', $issuer->currentCert);

            if ($issuerAltName !== false) {
                $this->setExtension('id-ce-issuerAltName', $issuerAltName);
            }
        }

        if (empty($tbsCertList['revokedCertificates'])) {
            unset($tbsCertList['revokedCertificates']);
        }

        unset($tbsCertList);

        // resync $this->signatureSubject
        // save $tbsCertList in case there are any \phpseclib3\File\ASN1\Element objects in it
        $tbsCertList = $this->currentCert['tbsCertList'];
        $this->loadCRL($this->saveCRL($this->currentCert));

        $result = $this->currentCert;
        $this->currentCert['signature'] = $result['signature'] = "\0" . $issuer->privateKey->sign($this->signatureSubject);
        $result['tbsCertList'] = $tbsCertList;

        $this->currentCert = $currentCert;
        $this->signatureSubject = $signatureSubject;

        return $result;
    }

    /**
     * Get a Revoked Certificate Extension
     *
     * Returns the extension if it exists and false if not
     */
    public function getRevokedCertificateExtension(string $serial, string $id, ?array $crl = null): string|false
    {
        if (!isset($crl)) {
            $crl = $this->currentCert;
        }

        if (is_array($rclist = Arrays::subArray($crl, 'tbsCertList/revokedCertificates'))) {
            if (($i = $this->revokedCertificate($rclist, $serial)) !== false) {
                return $this->getExtension($id, $crl, "tbsCertList/revokedCertificates/$i/crlEntryExtensions");
            }
        }

        return false;
    }

    /**
     * Get the index of a revoked certificate.
     */
    private function revokedCertificate(array &$rclist, string|BigInteger $serial, bool $create = false): int|false
    {
        if (is_string($serial)) {
            $serial = new BigInteger($serial);
        }

        foreach ($rclist as $i => $rc) {
            if (!($serial->compare($rc['userCertificate']))) {
                return $i;
            }
        }

        if (!$create) {
            return false;
        }

        $i = count($rclist);
        $revocationDate = new \DateTimeImmutable('now', new \DateTimeZone(@date_default_timezone_get()));
        $rclist[] = [
            'userCertificate' => $serial,
            'revocationDate'  => $this->timeField($revocationDate->format('D, d M Y H:i:s O'))
        ];
        return $i;
    }

    /**
     * Revoke a certificate.
     */
    public function revoke(string|BigInteger $serial, string|\DateTimeInterface|null $date = null): bool
    {
        if (isset($this->currentCert['tbsCertList'])) {
            if (is_array($rclist = &Arrays::subArray($this->currentCert, 'tbsCertList/revokedCertificates', true))) {
                if ($this->revokedCertificate($rclist, $serial) === false) { // If not yet revoked
                    if (($i = $this->revokedCertificate($rclist, $serial, true)) !== false) {
                        if (!empty($date)) {
                            // resolve relative dates like "+1 year" now. otherwise they'd be resolved every
                            // time the CRL is encoded, so the revocationDate signCRL() signs could differ from
                            // the one saveCRL() writes
                            if (is_string($date)) {
                                $date = new \DateTimeImmutable($date, new \DateTimeZone(@date_default_timezone_get()));
                                $date = $date->format('D, d M Y H:i:s O');
                            }
                            $rclist[$i]['revocationDate'] = $this->timeField($date);
                        }

                        return true;
                    }
                }
            }
        }

        return false;
    }
    /**
     * Sets how long a URL fetch can take, in seconds
     *
     * Covers the whole request, from looking up the host to reading the response,
     * and when a fetched issuer needs its own issuer fetched, that fetch only gets
     * the time that's left. Host name lookups can't be cut short, though, so a
     * slow DNS server can still make a fetch take longer. Defaults to 10 seconds.
     * With INF there's no limit, apart from giving up on a server that sends
     * nothing for an hour.
     */
    public static function setURLFetchTimeout(int|float $timeout): void
    {
        Newx509::setURLFetchTimeout($timeout);
        self::$urlFetchTimeout = $timeout;
    }

    /**
     * Sets the largest response a URL fetch accepts, in bytes
     *
     * Covers the headers as well as the certificate. Defaults to 64 KB.
     */
    public static function setURLFetchMaxSize(int $size): void
    {
        NewX509::setURLFetchMaxSize($size);
    }

    /**
     * Sets how long to wait for a URL fetch to connect, in seconds
     *
     * Defaults to 5 seconds, or less when less of setURLFetchTimeout()'s time is left.
     */
    public static function setURLFetchConnectTimeout(int|float $timeout): void
    {
        NewX509::setURLFetchMaxSize($timeout);
    }
}
