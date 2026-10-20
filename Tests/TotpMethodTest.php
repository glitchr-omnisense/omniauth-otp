<?php

namespace Omniauth\Totp\Tests;

use Omniauth\Context;
use Omniauth\Factor;
use Omniauth\Failure;
use Omniauth\Status;
use Omniauth\Testing\ArrayCache;
use Omniauth\Testing\FixedClock;
use Omniauth\Testing\InMemoryStore;
use Omniauth\Testing\TestAccount;
use Omniauth\Totp\CacheUsedSteps;
use Omniauth\Totp\Contract\SecretBox;
use Omniauth\Totp\SealedTotpSecrets;
use Omniauth\Totp\Testing\AuthenticatorApp;
use Omniauth\Totp\Tests\Fixtures\Kit;
use Omniauth\Totp\TotpMethod;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The authenticator application through the conductor, on the in-memory
 * stores: a password then a code; a code good once; the window; the
 * enrolment, its secret and its address; the revocation; the seam for sealed
 * secrets.
 */
final class TotpMethodTest extends TestCase
{
    /** RFC 6238, appendix B (SHA1), the last six digits of each code. */
    public static function rfcVectors(): iterable
    {
        yield [59, '287082'];
        yield [1111111109, '081804'];
        yield [1111111111, '050471'];
        yield [1234567890, '005924'];
        yield [2000000000, '279037'];
        yield [20000000000, '353130'];
    }

    #[DataProvider('rfcVectors')]
    public function testTheCodesAreRfc6238s(int $at, string $code): void
    {
        self::assertSame($code, (new Kit())->totp->code(Kit::TOTP_SECRET, $at));
    }

    public function testAPasswordThenACodeSignsIn(): void
    {
        $kit = new Kit();
        $context = new Context('https://example.org', 'example.org', '203.0.113.7');

        $first = $kit->omniauth->verify('password', $context, ['identifier' => 'ringo', 'password' => 'yellow-submarine']);
        self::assertSame(Status::SecondFactorRequired, $first->status);
        self::assertSame([Factor::Totp], $first->offered);

        $code = AuthenticatorApp::of(Kit::TOTP_SECRET, $kit->clock)->code();
        $result = $kit->omniauth->verify('totp', $context, ['code' => substr($code, 0, 3).' '.substr($code, 3)]);

        self::assertTrue($result->isAuthenticated());
        self::assertSame([Factor::Password, Factor::Totp], $result->passed);
        self::assertSame($kit->ringo, $result->account);
    }

    public function testAnAccountWithoutSecretIsAskedNothing(): void
    {
        $kit = new Kit();

        self::assertTrue($kit->omniauth->verify('password', new Context(), ['identifier' => 'paul', 'password' => 'let-it-be'])->isAuthenticated());
        self::assertFalse($kit->totp->enrolled($kit->paul));
        self::assertTrue($kit->totp->enrolled($kit->ringo));
    }

    public function testACodeIsAcceptedOnce(): void
    {
        $kit = new Kit();
        $code = AuthenticatorApp::of(Kit::TOTP_SECRET, $kit->clock)->code();

        self::assertTrue($this->signIn($kit, $code)->isAuthenticated());
        $kit->clock->advance(5);   // the same period: the code still verifies

        $again = $this->signIn($kit, $code);
        self::assertSame([Status::Failed, Failure::BadCode, 'replayed'], [$again->status, $again->failure, $again->reason], 'replayed, though otphp still accepts it');

        $kit->clock->advance(30);
        self::assertTrue($this->signIn($kit, AuthenticatorApp::of(Kit::TOTP_SECRET, $kit->clock)->code())->isAuthenticated(), 'the next period\'s code');
    }

    public function testTheSameCodeIsGoodForAnotherAccount(): void
    {
        $kit = new Kit();
        $kit->paul->totpSecret = Kit::TOTP_SECRET;
        $code = AuthenticatorApp::of(Kit::TOTP_SECRET, $kit->clock)->code();

        self::assertTrue($this->signIn($kit, $code)->isAuthenticated());
        self::assertTrue($this->signIn($kit, $code, 'paul', 'let-it-be')->isAuthenticated(), 'the step is claimed per account');
    }

    public function testNoCodeIsAcceptedFromTheWindowOnceALaterOneWas(): void
    {
        $kit = new Kit(leeway: 15, now: '2026-10-20 12:00:05 UTC');
        $app = AuthenticatorApp::of(Kit::TOTP_SECRET, $kit->clock);
        $previous = $app->code(-1);

        self::assertTrue($this->signIn($kit, $app->code())->isAuthenticated());
        $late = $this->signIn($kit, $previous);
        self::assertSame([Failure::BadCode, 'replayed'], [$late->failure, $late->reason], 'the previous period\'s code, inside the leeway, comes after the current one');
    }

    public function testTheLeewayIsSchebsSeconds(): void
    {
        // 12:00:05: the previous period ended 5 seconds ago.
        $strict = new Kit(leeway: 0, now: '2026-10-20 12:00:05 UTC');
        $previous = AuthenticatorApp::of(Kit::TOTP_SECRET, $strict->clock)->code(-1);
        self::assertSame(Failure::BadCode, $this->signIn($strict, $previous)->failure, 'leeway 0: only the current period');

        $lenient = new Kit(leeway: 10, now: '2026-10-20 12:00:05 UTC');
        self::assertTrue($this->signIn($lenient, $previous)->isAuthenticated(), '10 seconds of leeway reach back 5 seconds');

        $tooLate = new Kit(leeway: 4, now: '2026-10-20 12:00:05 UTC');
        self::assertSame(Failure::BadCode, $this->signIn($tooLate, $previous)->failure, '4 seconds do not');
    }

    public function testAWrongOrEmptyCodeIsABadCode(): void
    {
        $kit = new Kit(throttle: false);
        foreach (['000000', '', 'abcdef', '12345'] as $code) {
            $result = $this->signIn($kit, $code);
            self::assertSame([Status::Failed, Failure::BadCode], [$result->status, $result->failure], var_export($code, true));
        }
    }

    public function testFiveWrongCodesAndTheAccountIsThrottled(): void
    {
        $kit = new Kit();
        $kit->omniauth->verify('password', new Context(), ['identifier' => 'ringo', 'password' => 'yellow-submarine']);
        for ($i = 0; $i < 5; ++$i) {
            self::assertSame(Failure::BadCode, $kit->omniauth->verify('totp', new Context(), ['code' => '000000'])->failure);
        }

        self::assertSame(Failure::Throttled, $kit->omniauth->verify('totp', new Context(ip: '198.51.100.1'), ['code' => AuthenticatorApp::of(Kit::TOTP_SECRET, $kit->clock)->code()])->failure, 'per account, whatever the address');
    }

    public function testAnEnrolmentGivesASecretAndItsAddressThenKeepsTheSecret(): void
    {
        $kit = new Kit();
        $enrolment = $kit->omniauth->enrol(Factor::Totp, $kit->paul);

        $challenge = $enrolment->begin(new Context());
        self::assertSame('none', $challenge->kind);
        self::assertMatchesRegularExpression('~^[A-Z2-7]{52}$~', $challenge->data['secret'], 'scheb/2fa\'s secret: 32 bytes, base32, upper case, unpadded');
        self::assertSame('otpauth://totp/paul?secret='.$challenge->data['secret'], $challenge->data['uri']);
        self::assertNull($kit->paul->totpSecret, 'nothing kept before a first code');

        $app = AuthenticatorApp::scan($challenge->data['uri'], $kit->clock);
        self::assertSame('paul', $app->label());
        self::assertFalse($enrolment->confirm(new Context(), ['code' => '000000'])->isDone());
        self::assertTrue($enrolment->confirm(new Context(), ['code' => $app->code()])->isDone(), 'the secret survives a wrong code');
        self::assertSame($challenge->data['secret'], $kit->paul->totpSecret);

        $first = $kit->omniauth->verify('password', new Context(), ['identifier' => 'paul', 'password' => 'let-it-be']);
        self::assertSame([Factor::Totp], $first->offered, 'now asked');
        self::assertSame('replayed', $kit->omniauth->verify('totp', new Context(), ['code' => $app->code()])->reason, 'the enrolment\'s code is used');
        $kit->clock->advance(30);
        self::assertTrue($kit->omniauth->verify('totp', new Context(), ['code' => $app->code()])->isAuthenticated());
    }

    public function testAnEnrolmentNeverBegunHasNothingToConfirm(): void
    {
        $kit = new Kit();

        $enrolled = $kit->omniauth->enrol(Factor::Totp, $kit->paul)->confirm(new Context(), ['code' => '123456']);

        self::assertSame(Failure::Expired, $enrolled->failure);
    }

    public function testARevocationForgetsTheSecretAndTheTrustedDevices(): void
    {
        $kit = new Kit();
        $version = $kit->ringo->trustedVersion;

        self::assertTrue($kit->omniauth->revoke(Factor::Totp, $kit->ringo)->isDone());

        self::assertNull($kit->ringo->totpSecret);
        self::assertSame($version + 1, $kit->ringo->trustedVersion);
        self::assertTrue($kit->omniauth->verify('password', new Context(), ['identifier' => 'ringo', 'password' => 'yellow-submarine'])->isAuthenticated());
    }

    public function testTheAddressOfTheAccountsOwnSecret(): void
    {
        $kit = new Kit();

        self::assertSame('otpauth://totp/ringo?secret='.Kit::TOTP_SECRET, $kit->totp->uri($kit->ringo));
        self::assertNull($kit->totp->uri($kit->paul));

        $named = new TotpMethod($kit->store, $kit->secrets, new CacheUsedSteps(new ArrayCache()), issuer: 'Les Ringo Stars', server: 'lesringostars.com', clock: $kit->clock);
        self::assertSame('otpauth://totp/Les%20Ringo%20Stars%3Aringo%40lesringostars.com?issuer=Les%20Ringo%20Stars&secret='.Kit::TOTP_SECRET, $named->uri($kit->ringo));
    }

    public function testASealedStoreKeepsTheBoxsTextAndTheMethodReadsTheSecret(): void
    {
        $box = new class implements SecretBox {
            public function seal(string $secret): string
            {
                return 'sealed:'.strrev($secret);
            }

            public function open(string $stored): string
            {
                return str_starts_with($stored, 'sealed:') ? strrev(substr($stored, 7)) : $stored;
            }
        };
        $clock = new FixedClock();
        $store = new InMemoryStore($legacy = new TestAccount('1', 'ringo', totpSecret: Kit::TOTP_SECRET), $new = new TestAccount('2', 'paul'));
        $secrets = new SealedTotpSecrets($store->totpSecrets(), $box);
        $totp = new TotpMethod($store, $secrets, new CacheUsedSteps(new ArrayCache($clock)), clock: $clock);

        self::assertSame(Kit::TOTP_SECRET, $secrets->secret($legacy), 'a secret kept in clear before the box');
        $secrets->enable($new, 'JBSWY3DPEHPK3PXP');
        self::assertSame('sealed:PXP3KPHEPD3YWSBJ', $new->totpSecret, 'what the store keeps');
        self::assertSame('otpauth://totp/paul?secret=JBSWY3DPEHPK3PXP', $totp->uri($new));
        self::assertTrue($totp->enrolled($new));
    }

    public function testTheLeewayStaysBelowThePeriod(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new TotpMethod(new InMemoryStore(), (new InMemoryStore())->totpSecrets(), new CacheUsedSteps(new ArrayCache()), leeway: 30);
    }

    private function signIn(Kit $kit, string $code, string $identifier = 'ringo', string $password = 'yellow-submarine'): \Omniauth\Result
    {
        $first = $kit->omniauth->verify('password', new Context(), ['identifier' => $identifier, 'password' => $password]);
        self::assertSame(Status::SecondFactorRequired, $first->status);

        return $kit->omniauth->verify('totp', new Context(), ['code' => $code]);
    }
}
