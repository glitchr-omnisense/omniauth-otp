<?php

namespace Omniauth\Otp;

use Omniauth\Otp\Contract\UsedSteps;
use Psr\Cache\CacheItemPoolInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * The last time step each account used, in any PSR-6 pool or PSR-16 cache:
 * plain PHP, tests, and a host's cache pool (the same one its throttle uses
 * is fine). Each entry lives only as long as its code could still verify.
 *
 * Read then written, not atomic: two requests at the same instant with the
 * same code may both pass. The throttle (five tries in 15 minutes per account)
 * bounds what that leaves; a host that needs it exact keeps the steps where it
 * can lock.
 */
final class CacheUsedSteps implements UsedSteps
{
    public function __construct(
        private readonly CacheItemPoolInterface|CacheInterface $cache,
        private readonly string $prefix = 'omniauth.totp.',
    ) {
    }

    public function claim(string $handle, int $step, int $ttl): bool
    {
        $id = $this->prefix.hash('sha256', $handle);
        $last = $this->cache instanceof CacheItemPoolInterface ? $this->cache->getItem($id)->get() : $this->cache->get($id);
        if (\is_int($last) && $last >= $step) {
            return false;
        }
        $ttl = max(1, $ttl);
        if ($this->cache instanceof CacheItemPoolInterface) {
            $this->cache->save($this->cache->getItem($id)->set($step)->expiresAfter($ttl));
        } else {
            $this->cache->set($id, $step, $ttl);
        }

        return true;
    }
}
