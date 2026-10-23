<?php

namespace Omniauth\Otp\Contract;

/**
 * The time steps whose code an account already used: a code is accepted once
 * (RFC 6238 §5.2), and none older than the last one accepted. Omniauth\Otp\CacheUsedSteps
 * keeps them in any PSR-6 pool or PSR-16 cache; a host may keep them anywhere
 * else (a column, its rate limiter's store).
 */
interface UsedSteps
{
    /**
     * Claims the code of $step for the account of $handle: true the first
     * time, false when that step or a later one was already claimed.
     *
     * @param int $ttl how long, in seconds, the claim must be remembered: past
     *                 it the code of that step no longer verifies anyway
     */
    public function claim(string $handle, int $step, int $ttl): bool;
}
