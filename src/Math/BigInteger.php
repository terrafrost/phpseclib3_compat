<?php

/**
 * Pure-PHP arbitrary precision integer arithmetic library.
 *
 * Supports base-2, base-10, base-16, and base-256 numbers.  Uses the GMP or BCMath extensions, if available,
 * and an internal implementation, otherwise.
 *
 * Here's an example of how to use this library:
 * <code>
 * <?php
 *    $a = new \phpseclib3\Math\BigInteger(2);
 *    $b = new \phpseclib3\Math\BigInteger(3);
 *
 *    $c = $a->add($b);
 *
 *    echo $c->toString(); // outputs 5
 * ?>
 * </code>
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

namespace phpseclib3\Math;

use phpseclib4\Math\BigInteger as BigInteger2;

/**
 * Pure-PHP arbitrary precision integer arithmetic library. Supports base-2, base-10, base-16, and base-256
 * numbers.
 *
 * @author Jim Wigginton <terrafrost@php.net>
 */
class BigInteger extends BigInteger2
{
}
