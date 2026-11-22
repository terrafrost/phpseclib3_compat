<?php

/**
 * Pure-PHP ASN.1 Parser
 *
 * ASN.1 provides the semantics for data encoded using various schemes.  The most commonly
 * utilized scheme is DER or the "Distinguished Encoding Rules".  PEM's are base64 encoded
 * DER blobs.
 *
 * \phpseclib3\File\ASN1 decodes and encodes DER formatted messages and places them in a semantic context.
 *
 * Uses the 1988 ASN.1 syntax.
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      https://phpseclib.com/
 */

namespace phpseclib3\File;

use phpseclib4\File\ASN1 as NewASN1;

/**
 * Pure-PHP ASN.1 Parser
 *
 * @author Jim Wigginton <terrafrost@php.net>
 */
abstract class ASN1
{
    // Tag Classes
    // http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf#page=12
    const CLASS_UNIVERSAL        = 0;
    const CLASS_APPLICATION      = 1;
    const CLASS_CONTEXT_SPECIFIC = 2;
    const CLASS_PRIVATE          = 3;

    // Tag Classes
    // http://www.obj-sys.com/asn1tutorial/node124.html
    const TYPE_BOOLEAN           = 1;
    const TYPE_INTEGER           = 2;
    const TYPE_BIT_STRING        = 3;
    const TYPE_OCTET_STRING      = 4;
    const TYPE_NULL              = 5;
    const TYPE_OBJECT_IDENTIFIER = 6;
    //const TYPE_OBJECT_DESCRIPTOR = 7;
    //const TYPE_INSTANCE_OF       = 8; // EXTERNAL
    const TYPE_REAL              = 9;
    const TYPE_ENUMERATED        = 10;
    //const TYPE_EMBEDDED          = 11;
    const TYPE_UTF8_STRING       = 12;
    //const TYPE_RELATIVE_OID      = 13;
    const TYPE_SEQUENCE          = 16; // SEQUENCE OF
    const TYPE_SET               = 17; // SET OF

    // More Tag Classes
    // http://www.obj-sys.com/asn1tutorial/node10.html
    const TYPE_NUMERIC_STRING   = 18;
    const TYPE_PRINTABLE_STRING = 19;
    const TYPE_TELETEX_STRING   = 20; // T61String
    const TYPE_VIDEOTEX_STRING  = 21;
    const TYPE_IA5_STRING       = 22;
    const TYPE_UTC_TIME         = 23;
    const TYPE_GENERALIZED_TIME = 24;
    const TYPE_GRAPHIC_STRING   = 25;
    const TYPE_VISIBLE_STRING   = 26; // ISO646String
    const TYPE_GENERAL_STRING   = 27;
    const TYPE_UNIVERSAL_STRING = 28;
    //const TYPE_CHARACTER_STRING = 29;
    const TYPE_BMP_STRING       = 30;

    // Tag Aliases
    // These tags are kinda place holders for other tags.
    const TYPE_CHOICE = -1;
    const TYPE_ANY    = -2;

    /**
     * Default date format
     *
     * @link http://php.net/class.datetime
     */
    public static string $format = 'D, d M Y H:i:s O';

    /**
     * Set the time format
     *
     * Sets the time / date format for asn1map().
     */
    public static function setTimeFormat(string $format): void
    {
        self::$format = $format;
    }

    /**
     * DER-encode the OID
     *
     * Called by _encode_der()
     */
    public static function encodeOID(string $source): string
    {
        try {
            return NewASN1::encodeOID($source);
        } catch (\Exception $e) {
            throw new \RuntimeException($e->getMessage());
        }
    }

    /**
     * DER-encode the length
     *
     * DER supports lengths up to (2**8)**127, however, we'll only support lengths up to (2**8)**4.  See
     * {@link http://itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf#p=13 X.690 paragraph 8.1.3} for more information.
     */
    public static function encodeLength(int $length): string
    {
        return NewASN1::encodeLength($length);
    }

    /**
     * Returns the OID corresponding to a name
     *
     * What's returned in the associative array returned by loadX509() (or load*()) is either a name or an OID if
     * no OID to name mapping is available. The problem with this is that what may be an unmapped OID in one version
     * of phpseclib may not be unmapped in the next version, so apps that are looking at this OID may not be able
     * to work from version to version.
     *
     * This method will return the OID if a name is passed to it and if no mapping is avialable it'll assume that
     * what's being passed to it already is an OID and return that instead. A few examples.
     *
     * getOID('2.16.840.1.101.3.4.2.1') == '2.16.840.1.101.3.4.2.1'
     * getOID('id-sha256') == '2.16.840.1.101.3.4.2.1'
     * getOID('zzz') == 'zzz'
     */
    public static function getOID(string $name): string
    {
        return NewASN1::getOIDFromName($name);
    }

    /**
     * Extract raw BER from Base64 encoding
     */
    public static function extractBER(string $str): string
    {
        return NewASN1::extractBER($str);
    }

    /**
     * Load OIDs
     *
     * Load the relevant OIDs for a particular ASN.1 semantic mapping.
     * Previously loaded OIDs are retained.
     */
    public static function loadOIDs(array $oids): void
    {
        NewASN1::loadOIDs($oids);
    }
}
