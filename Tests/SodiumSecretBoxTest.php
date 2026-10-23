<?php

namespace Omniauth\Otp\Tests;

use Omniauth\ArrayState;
use Omniauth\Context;
use Omniauth\Factor;
use Omniauth\Method\Methods;
use Omniauth\Omniauth;
use Omniauth\Otp\CacheUsedSteps;
use Omniauth\Otp\Exception\UnreadableSecret;
use Omniauth\Otp\SealedTotpSecrets;
use Omniauth\Otp\SodiumSecretBox;
use Omniauth\Otp\Testing\AuthenticatorApp;
use Omniauth\Otp\Tests\Fixtures\CountingBox;
use Omniauth\Otp\TotpMethod;
use Omniauth\Password\PasswordMethod;
use Omniauth\Status;
use Omniauth\Testing\ArrayCache;
use Omniauth\Testing\FixedClock;
use Omniauth\Testing\InMemoryStore;
use Omniauth\Testing\TestAccount;
use PHPUnit\Framework\TestCase;
use Symfony\Component\PasswordHasher\Hasher\NativePasswordHasher;

/** The TOTP secrets sealed at rest with sodium (QA5): the format, the key, and a whole enrolment and sign-in on a sealed store. */
final class SodiumSecretBoxTest extends TestCase
{
    private const SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW';   // 52 characters, as TotpMethod::secret() draws them

    public function testASecretIsSealedUnderTheFormatsPrefixAndOpensBack(): void
    {
        $box = new SodiumSecretBox(str_repeat("\x07", 32));
        $sealed = $box->seal(self::SECRET);

        self::assertStringStartsWith('otp:v1:', $sealed);
        self::assertMatchesRegularExpression('~^otp:v1:[A-Za-z0-9_-]+$~', $sealed, 'base64url, unpadded');
        self::assertSame(130, \strlen($sealed), 'user.secret (VARCHAR 255) holds it');
        self::assertStringNotContainsString(self::SECRET, $sealed);
        self::assertTrue(SodiumSecretBox::isSealed($sealed));
        self::assertSame(self::SECRET, $box->open($sealed));
        self::assertNotSame($sealed, $box->seal(self::SECRET), 'a new nonce each time');
        self::assertSame(self::SECRET, (new SodiumSecretBox(str_repeat("\x07", 32)))->open($sealed), 'the same key, another instance (another host)');
    }

    public function testASecretKeptInClearBeforeTheBoxIsReadAsItIsAndASealedOneIsNotSealedTwice(): void
    {
        $box = new SodiumSecretBox(str_repeat("\x07", 32));

        self::assertFalse(SodiumSecretBox::isSealed(self::SECRET));
        self::assertSame(self::SECRET, $box->open(self::SECRET));
        $sealed = $box->seal(self::SECRET);
        self::assertSame($sealed, $box->seal($sealed), 'a rewrite of the rows runs twice harmlessly');
    }

    public function testAnotherKeyOrAnAlteredValueDoesNotOpen(): void
    {
        $sealed = (new SodiumSecretBox(str_repeat("\x07", 32)))->seal(self::SECRET);
        $other = new SodiumSecretBox(str_repeat("\x08", 32));
        foreach ([
            'another key' => [$other, $sealed],
            'altered' => [new SodiumSecretBox(str_repeat("\x07", 32)), substr($sealed, 0, -2).('AA' === substr($sealed, -2) ? 'BA' : 'AA')],
            'truncated' => [new SodiumSecretBox(str_repeat("\x07", 32)), 'otp:v1:AAAA'],
            'not base64' => [new SodiumSecretBox(str_repeat("\x07", 32)), 'otp:v1:***'],
        ] as $case => [$box, $value]) {
            try {
                $box->open($value);
                self::fail($case);
            } catch (UnreadableSecret $e) {
                self::assertStringNotContainsString(self::SECRET, $e->getMessage(), $case);
            }
        }
    }

    public function testTheKeyIs32BytesGivenInBase64(): void
    {
        $key = SodiumSecretBox::generateKey();
        self::assertSame(32, \strlen((string) base64_decode($key, true)));
        $sealed = SodiumSecretBox::fromBase64($key)->seal(self::SECRET);
        self::assertSame(self::SECRET, SodiumSecretBox::fromBase64(rtrim(strtr($key, '+/', '-_'), '='))->open($sealed), 'URL-safe and unpadded too');
        self::assertNotSame(SodiumSecretBox::generateKey(), $key);

        foreach (['', 'not base64 at all!', base64_encode(str_repeat('k', 16)), base64_encode(str_repeat('k', 33))] as $wrong) {
            try {
                SodiumSecretBox::fromBase64($wrong);
                self::fail(var_export($wrong, true));
            } catch (\InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    /**
     * Enrolled from the settings, then signed in, on a sealed store: the
     * store keeps the box's text only; the rule asks whether the account has
     * a secret without opening it; the code is verified with the secret
     * opened; the settings' QR address is the secret's.
     */
    public function testAnEnrolmentAndASignInOnASealedStore(): void
    {
        $clock = new FixedClock('2026-10-23 12:00:10 UTC');
        $hasher = new NativePasswordHasher(cost: 4);
        $store = new InMemoryStore($ringo = new TestAccount('1', 'ringo', 'ringo@example.org', $hasher->hash('yellow-submarine')));
        $box = new CountingBox(new SodiumSecretBox(sodium_crypto_secretbox_keygen()));
        $secrets = new SealedTotpSecrets($store->totpSecrets(), $box);
        $totp = new TotpMethod($store, $secrets, new CacheUsedSteps(new ArrayCache($clock)), clock: $clock);
        $session = [];
        $omniauth = new Omniauth($store, new Methods([new PasswordMethod($store, $store, $hasher), $totp]), new ArrayState($session), clock: $clock);

        $enrolment = $omniauth->enrol(Factor::Totp, $ringo);
        $challenge = $enrolment->begin(new Context());
        [$uri, $secret] = [$challenge->data['uri'] ?? null, $challenge->data['secret'] ?? null];
        self::assertIsString($uri);
        self::assertIsString($secret);
        $app = AuthenticatorApp::scan($uri, $clock);
        self::assertTrue($enrolment->confirm(new Context(), ['code' => $app->code()])->isDone());
        self::assertTrue(SodiumSecretBox::isSealed((string) $ringo->totpSecret), 'the store keeps the box\'s text');
        self::assertStringNotContainsString($secret, (string) $ringo->totpSecret);

        $clock->advance(30);
        $box->opened = 0;
        $first = $omniauth->verify('password', new Context(), ['identifier' => 'ringo', 'password' => 'yellow-submarine']);
        self::assertSame([Status::SecondFactorRequired, [Factor::Totp]], [$first->status, $first->offered]);
        self::assertSame(0, $box->opened, 'whether the account has a secret is read without opening it');
        $done = $omniauth->verify('totp', new Context(), ['code' => $app->code()]);
        self::assertTrue($done->isAuthenticated());
        self::assertSame(1, $box->opened, 'opened to verify the code');
        self::assertSame($uri, $totp->uri($ringo), 'the QR code of the settings, from the opened secret');
    }

    public function testASecretThatDoesNotOpenIsNeverTakenForNoSecret(): void
    {
        $clock = new FixedClock();
        $hasher = new NativePasswordHasher(cost: 4);
        $sealed = (new SodiumSecretBox(str_repeat("\x07", 32)))->seal(self::SECRET);
        $store = new InMemoryStore($ringo = new TestAccount('1', 'ringo', 'ringo@example.org', $hasher->hash('yellow-submarine'), totpSecret: $sealed));
        $totp = new TotpMethod($store, new SealedTotpSecrets($store->totpSecrets(), new SodiumSecretBox(str_repeat("\x08", 32))), new CacheUsedSteps(new ArrayCache($clock)), clock: $clock);
        $session = [];
        $omniauth = new Omniauth($store, new Methods([new PasswordMethod($store, $store, $hasher), $totp]), new ArrayState($session), clock: $clock);

        self::assertSame(Status::SecondFactorRequired, $omniauth->verify('password', new Context(), ['identifier' => 'ringo', 'password' => 'yellow-submarine'])->status, 'the account still has its second factor');
        $this->expectException(UnreadableSecret::class);
        $omniauth->verify('totp', new Context(), ['code' => '123456']);
    }
}
