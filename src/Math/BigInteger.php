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

use phpseclib4\Math\BigInteger as BigIntegerNew;
use phpseclib4\Math\BigInteger\Engines\Engine;

/**
 * Pure-PHP arbitrary precision integer arithmetic library. Supports base-2, base-10, base-16, and base-256
 * numbers.
 *
 * @method string toString()
 * @method string toBytes(bool $twos_compliment = false)
 * @method string toHex(bool $twos_compliment = false)
 * @method string toBits(bool $twos_compliment = false)
 * @method BigInteger add(BigInteger $y)
 * @method BigInteger subtract(BigInteger $y)
 * @method BigInteger multiply(BigInteger $x)
 * @method BigInteger[] divide(BigInteger $y)
 * @method array{gcd: BigInteger, x: BigInteger, y: BigInteger} extendedGCD(BigInteger $n)
 * @method BigInteger gcd(BigInteger $n)
 * @method BigInteger abs()
 * @method void setPrecision(int $bits)
 * @method int|bool getPrecision()
 * @method BigInteger powMod(BigInteger $e, BigInteger $n)
 * @method BigInteger modPow(BigInteger $e, BigInteger $n)
 * @method int compare(BigInteger $y)
 * @method bool equals(BigInteger $x)
 * @method BigInteger bitwise_not()
 * @method BigInteger bitwise_and(BigInteger $x)
 * @method BigInteger bitwise_or(BigInteger $x)
 * @method BigInteger bitwise_xor(BigInteger $x)
 * @method BigInteger bitwise_rightShift(int $shift)
 * @method BigInteger bitwise_leftShift(int $shift)
 * @method BigInteger bitwise_leftRotate(int $shift)
 * @method BigInteger bitwise_rightRotate(int $shift)
 * @method int getLength()
 * @method int getLengthInBytes()
 * @method BigInteger root(int $n = 2)
 * @method BigInteger pow(BigInteger $n)
 * @method bool between(BigInteger $min, BigInteger $max)
 * @method bool isOdd()
 * @method bool testBit(int $x)
 * @method bool isNegative()
 * @method BigInteger negate()
 * @method BigInteger[] bitwise_split(int $split)
 * @method static void setEngine(string $main, array $modexps = ['DefaultEngine'])
 * @method static string[] getEngine()
 * @method static array{min: BigInteger, max: BigInteger} minMaxBits(int $bits)
 * @method static BigInteger random(int $size)
 * @method static BigInteger randomPrime(int $size)
 * @method static BigInteger randomRange(BigInteger $min, BigInteger $max)
 * @method static BigInteger min(BigInteger ...$nums)
 * @method static BigInteger max(BigInteger ...$nums)
 * @method static int scan1divide(BigInteger $r)
 * @author Jim Wigginton <terrafrost@php.net>
 */
class BigInteger implements \JsonSerializable
{
    /**
     * The phpseclib 4 BigInteger that does the actual work
     *
     * @var BigIntegerNew
     */
    private $value;

    /**
     * Converts base-2, base-10, base-16, and binary strings (base-256) to BigIntegers.
     *
     * If the second parameter - $base - is negative, then it will be assumed that the number's are encoded using
     * two's compliment.  The sole exception to this is -10, which is treated the same as 10 is.
     */
    public function __construct(string|int|BigInteger|BigIntegerNew|Engine $x = 0, int $base = 10)
    {
        if ($x instanceof self) {
            $this->value = clone $x->value;
        } elseif ($x instanceof BigIntegerNew) {
            $this->value = clone $x;
        } else {
            $this->value = new BigIntegerNew($x, $base);
        }
    }

    /**
     * Returns the underlying phpseclib 4 BigInteger
     *
     * Use this when handing a value off to phpseclib 4 APIs.  The returned object is not a copy, so calling
     * setPrecision() on it will affect this object as well.
     */
    public function toNew(): BigIntegerNew
    {
        return $this->value;
    }

    /**
     * Converts phpseclib 4 return values to phpseclib 3 return values
     *
     * BigIntegers are wrapped, arrays are walked and everything else is returned as-is
     */
    private static function wrap(mixed $x): mixed
    {
        if ($x instanceof BigIntegerNew) {
            return new static($x);
        }
        if (is_array($x)) {
            return array_map([static::class, 'wrap'], $x);
        }
        return $x;
    }

    /**
     * Converts phpseclib 3 arguments to phpseclib 4 arguments
     *
     * Objects are unwrapped without cloning: scan1divide() modifies its argument in place and that change needs
     * to be visible in the phpseclib 3 object that was passed in.
     */
    private static function unwrap(array $args): array
    {
        return array_map(function (mixed $arg): mixed {
            return $arg instanceof self ? $arg->value : $arg;
        }, $args);
    }

    /**
     *  __call() magic method
     *
     * Passes calls through to phpseclib4\Math\BigInteger
     */
    public function __call(string $name, array $args): mixed
    {
        return self::wrap($this->value->$name(...self::unwrap($args)));
    }

    /**
     *  __callStatic() magic method
     *
     * Passes static calls through to phpseclib4\Math\BigInteger
     */
    public static function __callStatic(string $name, array $args): mixed
    {
        return self::wrap(BigIntegerNew::$name(...self::unwrap($args)));
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
     *
     * Will be called, automatically, when print_r() or var_dump() are called
     */
    public function __debugInfo(): array
    {
        return $this->value->__debugInfo();
    }

    /**
     * Calculates modular inverses.
     *
     * Say you have (30 mod 17 * x mod 17) mod 17 == 1.  x can be found using modular inverses.
     */
    public function modInverse(BigInteger $n): BigInteger|false
    {
        $result = $this->value->modInverse($n->value);
        return $result === null ? false : new static($result);
    }

    /**
     * Generate a random prime number between a range
     *
     * If there's not a prime within the given range, false will be returned.
     */
    public static function randomRangePrime(BigInteger $min, BigInteger $max): BigInteger|bool
    {
        $result = BigIntegerNew::randomRangePrime($min->value, $max->value);
        return $result === null ? false : new static($result);
    }

    /**
     * Checks a number to see if it's prime
     *
     * Assuming the $t parameter is not set, this function has an error rate of 2**-80.  The main motivation for the
     * $t parameter is distributability.  BigInteger::randomPrime() can be distributed across multiple pageloads
     * on a website instead of just one.
     */
    public function isPrime(int|bool $t = false): bool
    {
        return $this->value->isPrime($t === false ? null : (int) $t);
    }

    /**
     * Create Recurring Modulo Function
     *
     * Sometimes it may be desirable to do repeated modulos with the same number outside of
     * modular exponentiation
     */
    public function createRecurringModuloFunction(): callable
    {
        $func = $this->value->createRecurringModuloFunction();
        return function (BigInteger $x) use ($func): BigInteger {
            return new static($func($x->value));
        };
    }

    /**
     *  __serialize() magic method
     *
     * @see self::__unserialize()
     */
    public function __serialize(): array
    {
        $result = ['hex' => $this->value->toHex(true)];
        $precision = $this->value->getPrecision();
        if ($precision > 0) {
            $result['precision'] = $precision;
        }
        return $result;
    }

    /**
     *  __unserialize() magic method
     *
     * Also accepts strings produced by phpseclib 3's __sleep(), where hex and precision were private
     * properties (and thus have mangled names).
     *
     * @see self::__serialize()
     */
    public function __unserialize(array $data): void
    {
        $prefix = "\0" . self::class . "\0";
        $hex = $data['hex'] ?? $data[$prefix . 'hex'] ?? '';
        $precision = $data['precision'] ?? $data[$prefix . 'precision'] ?? null;

        $this->value = new BigIntegerNew($hex, -16);
        if ($precision > 0) {
            $this->value->setPrecision($precision);
        }
    }

    /**
     * JSON Serialize
     *
     * Will be called, automatically, when json_encode() is called on a BigInteger object.
     *
     * @return array{hex: string, precision?: int}
     */
    public function jsonSerialize(): array
    {
        return $this->value->jsonSerialize();
    }

    /**
     * Clone
     */
    public function __clone(): void
    {
        $this->value = clone $this->value;
    }
}
