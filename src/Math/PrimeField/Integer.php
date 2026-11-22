<?php

/**
 * Prime Finite Fields
 *
 * PHP version 8.1+
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2017-2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

namespace phpseclib3\Math\PrimeField;

use phpseclib3\Math\BigInteger;
use phpseclib3\Math\Common\FiniteField\Integer as Base;
use phpseclib4\Exception\UnexpectedValueException;
use phpseclib4\Math\BigInteger as BigIntegerNew;
use phpseclib4\Math\PrimeField\Integer as IntegerNew;

/**
 * Prime Finite Fields
 *
 * @method bool equals(Integer $x)
 * @method int compare(Integer $x)
 * @method Integer add(Integer $x)
 * @method Integer subtract(Integer $x)
 * @method Integer multiply(Integer $x)
 * @method Integer divide(Integer $x)
 * @method Integer pow(BigInteger $x)
 * @method bool isOdd()
 * @method Integer negate()
 * @method string toBytes()
 * @method string toBits()
 * @method array<int, int> getNAF(int $w = 1)
 * @method BigInteger toBigInteger()
 * @method static void setModulo(int $instanceID, BigInteger $modulo)
 * @method static void cleanupCache(int $instanceID)
 * @method static BigInteger getModulo(int $instanceID)
 * @method static void checkInstance(Integer $x, Integer $y)
 * @author Jim Wigginton <terrafrost@php.net>
 */
class Integer extends Base
{
    /**
     * The phpseclib 4 PrimeField\Integer that does the actual work
     */
    private IntegerNew $value;

    /**
     * Default constructor
     *
     * @param int|IntegerNew $instanceID
     * @param BigInteger $num
     */
    public function __construct(int|IntegerNew $instanceID, ?BigInteger $num = null)
    {
        $this->value = $instanceID instanceof IntegerNew ?
            $instanceID :
            new IntegerNew($instanceID, $num?->toNew());
    }

    /**
     * Returns the underlying phpseclib 4 PrimeField\Integer
     */
    public function toNew(): IntegerNew
    {
        return $this->value;
    }

    /**
     * Set the modulo for a given instance
     */
    public static function setRecurringModuloFunction(int $instanceID, callable $function): void
    {
        IntegerNew::setRecurringModuloFunction($instanceID, function (BigIntegerNew $x) use ($function): BigIntegerNew {
            return $function(new BigInteger($x))->toNew();
        });
    }

    /**
     * Calculates the square root
     *
     * @link https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm
     * @return static|false
     */
    public function squareRoot(): static|false
    {
        $result = self::translate(fn () => $this->value->squareRoot());
        return $result === null ? false : new static($result);
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
     * phpseclib 3 threw \UnexpectedValueException when two Integers from different PrimeFields were used together
     */
    private static function translate(callable $func): mixed
    {
        try {
            return $func();
        } catch (UnexpectedValueException $e) {
            throw new \UnexpectedValueException($e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     *  __call() magic method
     *
     * Passes calls through to phpseclib4\Math\PrimeField\Integer
     */
    public function __call(string $name, array $args): mixed
    {
        return self::wrap(self::translate(fn () => $this->value->$name(...self::unwrap($args))));
    }

    /**
     *  __callStatic() magic method
     *
     * Passes static calls through to phpseclib4\Math\PrimeField\Integer
     */
    public static function __callStatic(string $name, array $args): mixed
    {
        return self::wrap(self::translate(fn () => IntegerNew::$name(...self::unwrap($args))));
    }
}
