<?php

namespace Omniauth\Totp\Tests;

use Omniauth\Attempt;
use Omniauth\Context;
use Omniauth\Proof;
use Omniauth\Testing\ArrayCache;
use Omniauth\Testing\FixedClock;
use Omniauth\Testing\InMemoryStore;
use Omniauth\Testing\TestAccount;
use Omniauth\Totp\CacheUsedSteps;
use Omniauth\Totp\Tests\Fixtures\Kit;
use Omniauth\Totp\Tests\Fixtures\SchebUser;
use Omniauth\Totp\TotpMethod;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\Totp\TotpAuthenticator;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\Totp\TotpFactory;
use Symfony\Component\EventDispatcher\EventDispatcher;

/**
 * omniauth/totp against scheb/2fa itself (the harness installs it beside),
 * configured as every site configures it today: omnibase's User (SHA1, 30
 * seconds, 6 digits, the identifier as the label), `leeway: 0`, no server
 * name, no issuer. The secrets scheb draws work here, the codes it accepts
 * are accepted here - the first time - and those it refuses are refused; the
 * address of the QR code is the same.
 */
final class SchebCompatibilityTest extends TestCase
{
    /**
     * Written by scheb/2fa 8.6.1 (otphp 11.5.0): TotpFactory::createTotpForUser()->at()
     * for a SchebUser of Kit::TOTP_SECRET, and getQRContent() with no server name nor issuer.
     */
    private const SCHEB_CODES = [1792497600 => '678038', 1792497629 => '678038', 1792497630 => '442719', 1792497659 => '442719', 1792497660 => '730415'];
    private const SCHEB_URI = 'otpauth://totp/ringo?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

    public function testASecretSchebDrewAndACodeSchebAcceptsSignInOnce(): void
    {
        self::needsScheb();
        $clock = new FixedClock('2026-10-20 12:00:10 UTC');
        $scheb = self::scheb($clock);
        $secret = $scheb->generateSecret();
        $user = new SchebUser($secret);
        $code = (new TotpFactory(null, null, [], $clock))->createTotpForUser($user)->now();
        self::assertTrue($scheb->checkCode($user, $code), 'scheb accepts it');
        self::assertTrue($scheb->checkCode($user, $code), 'scheb accepts it again: it has no replay check');

        $kit = new Kit(now: '2026-10-20 12:00:10 UTC');
        $kit->paul->totpSecret = $secret;   // the row as it is today: user.secret, base32
        $kit->omniauth->verify('password', new Context(), ['identifier' => 'paul', 'password' => 'let-it-be']);
        self::assertTrue($kit->omniauth->verify('totp', new Context(), ['code' => $code])->isAuthenticated(), 'omniauth accepts it');

        $kit->omniauth->verify('password', new Context(), ['identifier' => 'paul', 'password' => 'let-it-be']);
        self::assertSame('replayed', $kit->omniauth->verify('totp', new Context(), ['code' => $code])->reason, 'and refuses it the second time');
    }

    /** @return iterable<string, array{int}> */
    public static function leeways(): iterable
    {
        yield 'leeway 0 (every site)' => [0];
        yield 'leeway 5' => [5];
        yield 'leeway 29' => [29];
    }

    /**
     * Across two period boundaries, second by second, every code of the
     * periods around and a wrong one: scheb's checkCode() and a first use
     * here answer the same.
     */
    #[DataProvider('leeways')]
    public function testWhatSchebAcceptsIsAcceptedAndWhatItRefusesIsRefused(int $leeway): void
    {
        self::needsScheb();
        $clock = new FixedClock();
        $user = new SchebUser(Kit::TOTP_SECRET);
        $scheb = self::scheb($clock, $leeway);
        $factory = new TotpFactory(null, null, [], $clock);
        $account = new TestAccount('1', 'ringo', totpSecret: Kit::TOTP_SECRET);
        $store = new InMemoryStore($account);
        $start = 1792497600 - 35;
        $compared = 0;
        for ($now = $start; $now <= $start + 70; ++$now) {
            $clock->set(new \DateTimeImmutable('@'.$now));
            $codes = ['000000', ' '.$factory->createTotpForUser($user)->now()];
            foreach ([-60, -30, -15, 15, 30, 60] as $shift) {
                $codes[] = $factory->createTotpForUser($user)->at($now + $shift);
            }
            foreach (array_unique($codes) as $code) {
                $method = new TotpMethod($store, $store->totpSecrets(), new CacheUsedSteps(new ArrayCache($clock)), $leeway, clock: $clock);
                $attempt = new Attempt($now);
                $attempt->identify($account, '1');
                self::assertSame($scheb->checkCode($user, $code), $method->verify($attempt, new Proof(['code' => $code]), new Context())->hasPassed(), \sprintf('at %d, leeway %d, code %s', $now, $leeway, $code));
                ++$compared;
            }
        }
        self::assertGreaterThan(300, $compared);
    }

    /** Recorded: needs no scheb/2fa. */
    public function testTheCodesAndTheAddressSchebRecordedAreTheOnesHere(): void
    {
        $kit = new Kit();
        foreach (self::SCHEB_CODES as $at => $code) {
            self::assertSame($code, $kit->totp->code(Kit::TOTP_SECRET, $at), (string) $at);
        }
        self::assertSame(self::SCHEB_URI, $kit->totp->uri($kit->ringo));
        foreach (self::SCHEB_CODES as $at => $code) {
            $then = new Kit(now: '@'.$at);
            $attempt = new Attempt($at);
            $attempt->identify($then->ringo, '1');
            self::assertTrue($then->totp->verify($attempt, new Proof(['code' => $code]), new Context())->hasPassed(), 'accepted at '.$at);
        }
    }

    /** @return iterable<string, array{?string, ?string}> */
    public static function labels(): iterable
    {
        yield 'as every site: no server name, no issuer' => [null, null];
        yield 'a server name' => ['lesringostars.com', null];
        yield 'an issuer' => [null, 'Les Ringo Stars'];
        yield 'both' => ['lesringostars.com', 'Les Ringo Stars'];
    }

    #[DataProvider('labels')]
    public function testTheQrCodesAddressIsSchebs(?string $server, ?string $issuer): void
    {
        self::needsScheb();
        $clock = new FixedClock();
        $scheb = new TotpAuthenticator(new TotpFactory($server, $issuer, [], $clock), new EventDispatcher(), 0);
        $store = new InMemoryStore($account = new TestAccount('1', 'ringo', totpSecret: Kit::TOTP_SECRET));
        $method = new TotpMethod($store, $store->totpSecrets(), new CacheUsedSteps(new ArrayCache()), issuer: $issuer, server: $server, clock: $clock);

        self::assertSame($scheb->getQRContent(new SchebUser(Kit::TOTP_SECRET)), $method->uri($account));
    }

    public function testASecretIsDrawnAsSchebDrawsIt(): void
    {
        self::needsScheb();
        $scheb = self::scheb(new FixedClock());

        foreach ([$scheb->generateSecret(), TotpMethod::secret()] as $secret) {
            self::assertMatchesRegularExpression('~^[A-Z2-7]{52}$~', $secret);
            self::assertSame(32, \strlen(\ParagonIE\ConstantTime\Base32::decodeUpper($secret)));
        }
    }

    private static function needsScheb(): void
    {
        if (!class_exists(TotpAuthenticator::class)) {
            self::markTestSkipped('scheb/2fa is not installed (the harness installs it).');
        }
    }

    private static function scheb(FixedClock $clock, int $leeway = 0): TotpAuthenticator
    {
        // As scheb_two_factor.yaml leaves it on every site: no server_name, no issuer, no parameters.
        return new TotpAuthenticator(new TotpFactory(null, null, [], $clock), new EventDispatcher(), $leeway);
    }
}
