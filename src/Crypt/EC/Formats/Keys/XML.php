<?php

/**
 * XML Formatted EC Key Handler
 *
 * More info:
 *
 * https://www.w3.org/TR/xmldsig-core/#sec-ECKeyValue
 * http://en.wikipedia.org/wiki/XML_Signature
 *
 * PHP version 8.1+
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib3\Crypt\EC\Formats\Keys;

use phpseclib4\Crypt\EC\Formats\Keys\XML as XMLNew;

/**
 * XML Formatted EC Key Handler
 *
 * @method static void enableRFC4050Syntax()
 * @author Jim Wigginton <terrafrost@php.net>
 */
abstract class XML
{
    public static function __callStatic(string $name, array $args): mixed
    {
        return XMLNew::$name(...$args);
    }
}