<?php

/**
 * Binary Finite Fields
 *
 * Utilizes the factory design pattern
 *
 * PHP version 8.1+
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2017-2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

namespace phpseclib3\Math;

use phpseclib3\Math\BinaryField\Integer;
use phpseclib3\Math\Common\FiniteField;
use phpseclib4\Exception\ResourceLimitException;
use phpseclib4\Exception\UnsupportedValueException;
use phpseclib4\Math\BigInteger as BigIntegerNew;
use phpseclib4\Math\BinaryField as BinaryFieldNew;
use phpseclib4\Math\BinaryField\Integer as IntegerNew;

/**
 * Binary Finite Fields
 *
 * @method Integer newInteger(BigInteger|string $num)
 * @method Integer randomInteger()
 * @method int getLengthInBytes()
 * @method int getLength()
 * @method static string base2ToBase256(string $x, ?int $size = null)
 * @method static string base256ToBase2(string $x)
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class BinaryField extends FiniteField
{
    /**
     * The phpseclib 4 BinaryField that does the actual work
     */
    private BinaryFieldNew $value;

    /**
     * Default constructor
     */
    public function __construct(int ...$indices)
    {
        // phpseclib 3 threw \OutOfBoundsException for degrees > 571 and \InvalidArgumentException for
        // degrees < 1 / out of range exponents. ResourceLimitException extends UnsupportedValueException
        // so it has to be caught first
        try {
            $this->value = new BinaryFieldNew(...$indices);
        } catch (ResourceLimitException $e) {
            throw new \OutOfBoundsException($e->getMessage(), $e->getCode(), $e);
        } catch (UnsupportedValueException $e) {
            throw new \InvalidArgumentException($e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * Returns the underlying phpseclib 4 BinaryField
     */
    public function toNew(): BinaryFieldNew
    {
        return $this->value;
    }

    /**
     * Converts phpseclib 4 return values to phpseclib 3 return values
     */
    private static function wrap(mixed $x): mixed
    {
        if ($x instanceof IntegerNew) {
            return new Integer($x);
        }
        if ($x instanceof BigIntegerNew) {
            return new BigInteger($x);
        }
        if (is_array($x)) {
            return array_map([self::class, 'wrap'], $x);
        }
        return $x;
    }

    /**
     * Converts phpseclib 3 arguments to phpseclib 4 arguments
     */
    private static function unwrap(array $args): array
    {
        return array_map(function (mixed $arg): mixed {
            return $arg instanceof BigInteger || $arg instanceof Integer ? $arg->toNew() : $arg;
        }, $args);
    }

    /**
     *  __call() magic method
     *
     * Passes calls through to phpseclib4\Math\BinaryField
     */
    public function __call(string $name, array $args): mixed
    {
        return self::wrap($this->value->$name(...self::unwrap($args)));
    }

    /**
     *  __callStatic() magic method
     *
     * Passes static calls through to phpseclib4\Math\BinaryField
     */
    public static function __callStatic(string $name, array $args): mixed
    {
        return self::wrap(BinaryFieldNew::$name(...self::unwrap($args)));
    }
}
