<?php

namespace Omniauth\Totp;

use OTPHP\TOTP;
use Omniauth\Attempt;
use Omniauth\Context;
use Omniauth\Contract\Accounts;
use Omniauth\Contract\TotpSecrets;
use Omniauth\Enrolled;
use Omniauth\Factor;
use Omniauth\Failure;
use Omniauth\Method\Challenge;
use Omniauth\Method\Enrolling;
use Omniauth\Method\Revocable;
use Omniauth\Method\SecondFactor;
use Omniauth\Method\Verdict;
use Omniauth\Proof;
use Omniauth\SystemClock;
use Omniauth\Totp\Contract\UsedSteps;
use ParagonIE\ConstantTime\Base32;
use Psr\Clock\ClockInterface;

/**
 * An authenticator application (TOTP, RFC 6238) as a second factor, over
 * spomky-labs/otphp - the library scheb/2fa verifies with, on the parameters
 * omnibase's User gives it (SHA1, 30 seconds, 6 digits) and the leeway every
 * site sets (0): a code scheb accepts, this accepts, and the secrets kept
 * today (user.secret, base32) go on working. One thing more than scheb: a
 * code is accepted once, and none older than the last one accepted
 * (Contract\UsedSteps).
 *
 * verify(): ['code' => '123 456'] (spaces ignored). Enrolment: enrolBegin()
 * draws a secret as scheb does and gives it with its otpauth:// address
 * (Challenge::$data: 'secret', 'uri' - the host draws the QR code of 'uri');
 * enrolConfirm() checks a first code against it and keeps it in the store.
 * revoke() forgets it. Secrets go through Contract\TotpSecrets as they are;
 * SealedTotpSecrets is the seam for sealing them at rest (QA5).
 */
final class TotpMethod implements SecondFactor, Enrolling, Revocable
{
    /** scheb/2fa's TOTP, as omnibase's User configures it and every site's scheb_two_factor.yaml leaves it. */
    public const ALGORITHM = 'sha1';
    public const PERIOD = 30;
    public const DIGITS = 6;
    public const LEEWAY = 0;

    private readonly ClockInterface $clock;

    /**
     * @param int         $leeway seconds a code is accepted before and after its period (scheb's `leeway`), lower than the period
     * @param string|null $issuer scheb's `issuer`: shown by the application
     * @param string|null $server scheb's `server_name`: appended to the label, "ringo@example.org"
     */
    public function __construct(
        private readonly Accounts $accounts,
        private readonly TotpSecrets $secrets,
        private readonly UsedSteps $used,
        private readonly int $leeway = self::LEEWAY,
        private readonly int $period = self::PERIOD,
        private readonly int $digits = self::DIGITS,
        private readonly string $algorithm = self::ALGORITHM,
        private readonly ?string $issuer = null,
        private readonly ?string $server = null,
        ?ClockInterface $clock = null,
    ) {
        if ($period < 1 || $leeway < 0 || $leeway >= $period) {
            throw new \InvalidArgumentException('A TOTP has a period of a second or more and a leeway from 0 to less than its period.');
        }
        if ($digits < 6 || $digits > 10) {
            throw new \InvalidArgumentException('A TOTP code has 6 to 10 digits.');
        }
        $this->clock = $clock ?? new SystemClock();
    }

    public function factor(): Factor
    {
        return Factor::Totp;
    }

    public function enrolled(object $account): bool
    {
        return '' !== (string) $this->secrets->secret($account);
    }

    public function verify(Attempt $attempt, Proof $proof, Context $context): Verdict
    {
        $account = $attempt->account();
        if (null === $account) {
            return Verdict::refused(Failure::NoAttempt);
        }
        $secret = (string) $this->secrets->secret($account);
        if ('' === $secret) {
            return Verdict::refused(Failure::NotEnrolled);
        }
        $failure = $this->check($account, $secret, $proof);

        return null === $failure ? Verdict::passed($account) : Verdict::refused(...$failure);
    }

    public function enrolBegin(Attempt $enrolment, Proof $proof, Context $context): Challenge
    {
        $account = $enrolment->account() ?? throw new \LogicException('An enrolment has its account.');
        $secret = self::secret();
        $enrolment->keep(Factor::Totp, $secret);

        return Challenge::none(['secret' => $secret, 'uri' => $this->uri($account, $secret)]);
    }

    public function enrolConfirm(Attempt $enrolment, Proof $proof, Context $context): Enrolled
    {
        $account = $enrolment->account() ?? throw new \LogicException('An enrolment has its account.');
        $secret = $enrolment->kept(Factor::Totp);
        if (!\is_string($secret) || '' === $secret) {
            return Enrolled::failed(Failure::Expired);
        }
        $failure = $this->check($account, $secret, $proof);
        if (null !== $failure) {
            return Enrolled::failed(...$failure);
        }
        $this->secrets->enable($account, $secret);
        $enrolment->take(Factor::Totp);

        return Enrolled::done();
    }

    public function revoke(object $account): void
    {
        $this->secrets->disable($account);
    }

    /**
     * The otpauth:// address an application scans, the same scheb/2fa's
     * TotpAuthenticator::getQRContent() gives: the label is the account's
     * identifier (omnibase's getTotpAuthenticationUsername()), "@" and the
     * server name when one is set; the issuer when one is set. Of the
     * account's own secret when none is given (the settings' QR code), or
     * null when it has none.
     */
    public function uri(object $account, #[\SensitiveParameter] ?string $secret = null): ?string
    {
        $secret ??= $this->secrets->secret($account);
        if (null === $secret || '' === $secret) {
            return null;
        }
        $totp = $this->totp($secret);
        $label = $this->accounts->identifier($account);
        $server = (string) $this->server;
        $label .= ('' !== $label && '' !== $server ? '@' : '').$server;
        if ('' !== $label) {
            $totp->setLabel($label);
        }
        if (null !== $this->issuer && '' !== $this->issuer) {
            $totp->setIssuer($this->issuer);
            if (null === $totp->getLabel()) {
                $totp = $totp->withIssuerIncludedAsParameter(false);
            }
        }

        return $totp->getProvisioningUri();
    }

    /** The code of $secret at this moment (or at $timestamp): what the application shows. */
    public function code(#[\SensitiveParameter] string $secret, ?int $timestamp = null): string
    {
        return $this->totp($secret)->at($timestamp ?? $this->now());
    }

    /** A new secret as scheb/2fa draws it: 32 random bytes, base32, upper case, unpadded (52 characters). */
    public static function secret(): string
    {
        return Base32::encodeUpperUnpadded(random_bytes(32));
    }

    /**
     * Null when the code is good and its step claimed, else the failure and its reason.
     *
     * @return array{Failure, ?string}|null
     */
    private function check(object $account, #[\SensitiveParameter] string $secret, Proof $proof): ?array
    {
        $code = preg_replace('~\s+~', '', $proof->string('code')) ?? '';
        if ('' === $code) {
            return [Failure::BadCode, null];
        }
        $now = $this->now();
        try {
            $totp = $this->totp($secret);
            // otphp's own verification, as scheb/2fa calls it: what scheb accepts, this accepts.
            if (!$totp->verify($code, $now, $this->leeway)) {
                return [Failure::BadCode, null];
            }
            $step = null;
            foreach (array_unique([$now, $now - $this->leeway, $now + $this->leeway]) as $at) {
                if ($at >= 0 && hash_equals($totp->at($at), $code)) {
                    $step = intdiv($at, $this->period);
                    break;
                }
            }
        } catch (\InvalidArgumentException|\RuntimeException) {
            return [Failure::BadCode, 'unreadable-secret'];
        }
        if (null === $step) {
            return [Failure::BadCode, null];
        }
        // Past this moment the code of $step no longer verifies: the claim need not be remembered longer.
        $ttl = ($step + 1) * $this->period + $this->leeway - $now + 1;
        if (!$this->used->claim($this->accounts->handle($account), $step, $ttl)) {
            return [Failure::BadCode, 'replayed'];
        }

        return null;
    }

    private function totp(#[\SensitiveParameter] string $secret): TOTP
    {
        return TOTP::create($secret, $this->period, $this->algorithm, $this->digits, clock: $this->clock);
    }

    private function now(): int
    {
        return $this->clock->now()->getTimestamp();
    }
}
