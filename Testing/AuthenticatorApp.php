<?php

namespace Omniauth\Totp\Testing;

use OTPHP\Factory;
use OTPHP\TOTP;
use OTPHP\TOTPInterface;
use Psr\Clock\ClockInterface;

/**
 * An authenticator application in PHP, for tests: it scans the otpauth://
 * address an enrolment gives (or takes a secret) and shows the code of the
 * moment on the clock given - the code a person would type.
 */
final class AuthenticatorApp
{
    private function __construct(private readonly TOTPInterface $totp, private readonly ClockInterface $clock)
    {
    }

    /** The application after scanning the QR code of $uri. */
    public static function scan(string $uri, ClockInterface $clock): self
    {
        $totp = Factory::loadFromProvisioningUri($uri, $clock);
        if (!$totp instanceof TOTPInterface) {
            throw new \InvalidArgumentException('Not a TOTP address.');
        }

        return new self($totp, $clock);
    }

    /** The application with a secret typed in (SHA1, 30 seconds, 6 digits unless told). */
    public static function of(#[\SensitiveParameter] string $secret, ClockInterface $clock, int $period = 30, int $digits = 6, string $algorithm = 'sha1'): self
    {
        return new self(TOTP::create($secret, $period, $algorithm, $digits, clock: $clock), $clock);
    }

    /** The code shown now - or $periods periods from now (-1: the one before). */
    public function code(int $periods = 0): string
    {
        return $this->totp->at($this->clock->now()->getTimestamp() + $periods * $this->totp->getPeriod());
    }

    public function secret(): string
    {
        return $this->totp->getSecret();
    }

    public function label(): ?string
    {
        return $this->totp->getLabel();
    }
}
