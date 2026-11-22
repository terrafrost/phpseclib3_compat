<?php

/**
 * ASN.1 Raw Element
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      https://phpseclib.com/
 */

namespace phpseclib3\File\ASN1;

/**
 * ASN.1 Raw Element
 *
 * An ASN.1 ANY mapping will return an ASN1\Element object. Use of this object
 * will also bypass the normal encoding rules in ASN1::encodeDER()
 *
 * @author Jim Wigginton <terrafrost@php.net>
 */
class Element
{
    // in v3 it was ->element
    // in v4 it's ->value
    public function __construct(public string $element)
    {
    }
}
