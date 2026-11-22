<?php

/**
 * Binary Finite Fields
 *
 * In a binary finite field numbers are actually polynomial equations. If you
 * represent the number as a sequence of bits you get a sequence of 1's or 0's.
 * These 1's or 0's represent the coefficients of the x**n, where n is the
 * location of the given bit. When you add numbers over a binary finite field
 * the result should have a coefficient of 1 or 0 as well. Hence addition
 * and subtraction become the same operation as XOR.
 * eg. 1 + 1 + 1 == 3 % 2 == 1 or 0 - 1 == -1 % 2 == 1
 *
 * PHP version 8.1+
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2017-2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

namespace phpseclib3\Math\BinaryField;

use phpseclib3\Math\BigInteger;
use phpseclib3\Math\Common\FiniteField\Integer as Base;
use phpseclib4\Exception\InvalidArgumentException;
use phpseclib4\Math\BigInteger as BigIntegerNew;
use phpseclib4\Math\BinaryField\Integer as IntegerNew;

/**
 * Binary Finite Fields
 *
 * @method bool equals(Integer $x)
 * @method int compare(Integer $x)
 * @method Integer add(Integer $y)
 * @method Integer subtract(Integer $x)
 * @method Integer multiply(Integer $y)
 * @method Integer modInverse()
 * @method Integer divide(Integer $x)
 * @method Integer negate()
 * @method string toBytes()
 * @method string toBits()
 * @method BigInteger toBigInteger()
 * @method static void setModulo(int $instanceID, string $modulo)
 * @method static void setRecurringModuloFunction(int $instanceID, callable $function)
 * @method static string getModulo(int $instanceID)
 * @author Jim Wigginton <terrafrost@php.net>
 */
class Integer extends Base
{
    /**
     * The phpseclib 4 BinaryField\Integer that does the actual work
     */
    private IntegerNew $value;

    /**
     * Default constructor
     */
    public function __construct(int|IntegerNew $instanceID, string $num = '')
    {
        $this->value = $instanceID instanceof IntegerNew ?
            $instanceID :
            new IntegerNew($instanceID, $num);
    }

    /**
     * Returns the underlying phpseclib 4 BinaryField\Integer
     */
    public function toNew(): IntegerNew
    {
        return $this->value;
    }

    /**
     * Converts an Integer to a hex string (eg. base-16).
     */
    public function toHex(): string
    {
        return $this->value->toHex();
    }

    /**
     *  __toString() magic method
     */
    public function __toString(): string
    {
        return (string) $this->value;
    }

    /**
     *  __debugInfo() magic method
     */
    public function __debugInfo(): array
    {
        return $this->value->__debugInfo();
    }

    /**
     * Converts phpseclib 4 return values to phpseclib 3 return values
     */
    private static function wrap(mixed $x): mixed
    {
        if ($x instanceof IntegerNew) {
            return new static($x);
        }
        if ($x instanceof BigIntegerNew) {
            return new BigInteger($x);
        }
        if (is_array($x)) {
            return array_map([static::class, 'wrap'], $x);
        }
        return $x;
    }

    /**
     * Converts phpseclib 3 arguments to phpseclib 4 arguments
     */
    private static function unwrap(array $args): array
    {
        return array_map(function (mixed $arg): mixed {
            return $arg instanceof self || $arg instanceof BigInteger ? $arg->toNew() : $arg;
        }, $args);
    }

    /**
     * Runs a phpseclib 4 call, converting its exceptions to the ones phpseclib 3 threw
     *
     * phpseclib 3 threw \UnexpectedValueException when two Integers from different BinaryFields were used together
     */
    private static function translate(callable $func): mixed
    {
        try {
            return $func();
        } catch (InvalidArgumentException $e) {
            throw new \UnexpectedValueException($e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     *  __call() magic method
     *
     * Passes calls through to phpseclib4\Math\BinaryField\Integer
     */
    public function __call(string $name, array $args): mixed
    {
        return self::wrap(self::translate(fn () => $this->value->$name(...self::unwrap($args))));
    }

    /**
     *  __callStatic() magic method
     *
     * Passes static calls through to phpseclib4\Math\BinaryField\Integer
     */
    public static function __callStatic(string $name, array $args): mixed
    {
        return self::wrap(self::translate(fn () => IntegerNew::$name(...self::unwrap($args))));
    }
}
