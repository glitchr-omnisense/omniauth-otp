<?php

namespace Omniauth\Totp\Tests\Fixtures;

use Omniauth\ArrayState;
use Omniauth\BackupCode\BackupCodeMethod;
use Omniauth\CacheThrottle;
use Omniauth\Method\Methods;
use Omniauth\Omniauth;
use Omniauth\Password\PasswordMethod;
use Omniauth\Testing\ArrayCache;
use Omniauth\Testing\FixedClock;
use Omniauth\Testing\InMemoryStore;
use Omniauth\Testing\InMemoryTotpSecrets;
use Omniauth\Testing\TestAccount;
use Omniauth\Totp\CacheUsedSteps;
use Omniauth\Totp\TotpMethod;
use Omniauth\TrustedDevice\TrustedDevices;
use Symfony\Component\PasswordHasher\Hasher\NativePasswordHasher;

/**
 * omniauth with its authenticator application, on the in-memory stores: two
 * accounts (ringo has a TOTP secret, paul none), a password each, the
 * backup codes and the trusted devices beside, a fixed clock, a throttle and
 * the used steps on array caches.
 */
final class Kit
{
    public const SECRET = 'a-kernel-secret-of-thirty-two-bytes-or-more';
    /** RFC 6238's SHA1 seed, "12345678901234567890", in base32. */
    public const TOTP_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

    public readonly FixedClock $clock;
    public readonly InMemoryStore $store;
    public readonly InMemoryTotpSecrets $secrets;
    public readonly ArrayCache $steps;
    public readonly TotpMethod $totp;
    public readonly TestAccount $ringo;
    public readonly TestAccount $paul;
    public readonly Omniauth $omniauth;
    /** @var array<string, mixed> */
    public array $session = [];

    public function __construct(int $leeway = 0, string $now = '2026-10-20 12:00:10 UTC', bool $throttle = true)
    {
        $this->clock = new FixedClock($now);
        $hasher = new NativePasswordHasher(cost: 4);
        $this->store = new InMemoryStore(
            $this->ringo = new TestAccount('1', 'ringo', 'ringo@example.org', $hasher->hash('yellow-submarine'), totpSecret: self::TOTP_SECRET),
            $this->paul = new TestAccount('2', 'paul', 'paul@example.org', $hasher->hash('let-it-be')),
        );
        $this->secrets = $this->store->totpSecrets();
        $this->steps = new ArrayCache($this->clock);
        $this->totp = new TotpMethod($this->store, $this->secrets, new CacheUsedSteps($this->steps), $leeway, clock: $this->clock);
        $this->omniauth = new Omniauth(
            $this->store,
            new Methods([
                new PasswordMethod($this->store, $this->store, $hasher),
                $this->totp,
                new BackupCodeMethod($this->store),
                new TrustedDevices($this->store, $this->store, self::SECRET, clock: $this->clock),
            ]),
            new ArrayState($this->session),
            throttle: $throttle ? new CacheThrottle(new ArrayCache($this->clock), clock: $this->clock) : null,
            clock: $this->clock,
        );
    }
}
