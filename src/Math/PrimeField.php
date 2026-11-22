<?php

/**
 * Prime Finite Fields
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

use phpseclib3\Math\Common\FiniteField;
use phpseclib3\Math\PrimeField\Integer;
use phpseclib4\Exception\InvalidArgumentException;
use phpseclib4\Math\BigInteger as BigIntegerNew;
use phpseclib4\Math\PrimeField as PrimeFieldNew;
use phpseclib4\Math\PrimeField\Integer as IntegerNew;

/**
 * Prime Finite Fields
 *
 * @method Integer newInteger(BigInteger $num)
 * @method Integer randomInteger()
 * @method int getLengthInBytes()
 * @method int getLength()
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class PrimeField extends FiniteField
{
    /**
     * The phpseclib 4 PrimeField that does the actual work
     */
    private PrimeFieldNew $value;

    /**
     * Default constructor
     */
    public function __construct(BigInteger $modulo)
    {
        try {
            $this->value = new PrimeFieldNew($modulo->toNew());
        } catch (InvalidArgumentException $e) {
            // phpseclib 3 threw \UnexpectedValueException when the modulo wasn't prime
            throw new \UnexpectedValueException($e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * Returns the underlying phpseclib 4 PrimeField
     */
    public function toNew(): PrimeFieldNew
    {
        return $this->value;
    }

    /**
     * Use a custom defined modular reduction function
     */
    public function setReduction(\Closure $func): void
    {
        $func = $func->bindTo($this, $this);
        // phpseclib 4 binds this closure to its own PrimeField so the body can only use public APIs
        $this->value->setReduction(function (BigIntegerNew $x) use ($func): BigIntegerNew {
            return $func(new BigInteger($x))->toNew();
        });
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
     * Passes calls through to phpseclib4\Math\PrimeField
     */
    public function __call(string $name, array $args): mixed
    {
        return self::wrap($this->value->$name(...self::unwrap($args)));
    }

    /**
     *  __callStatic() magic method
     *
     * Passes static calls through to phpseclib4\Math\PrimeField
     */
    public static function __callStatic(string $name, array $args): mixed
    {
        return self::wrap(PrimeFieldNew::$name(...self::unwrap($args)));
    }
}
