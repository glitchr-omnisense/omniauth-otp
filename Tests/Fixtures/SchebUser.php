<?php

namespace Omniauth\Totp\Tests\Fixtures;

use Scheb\TwoFactorBundle\Model\Totp\TotpConfiguration;
use Scheb\TwoFactorBundle\Model\Totp\TotpConfigurationInterface;
use Scheb\TwoFactorBundle\Model\Totp\TwoFactorInterface;

/**
 * An account as scheb/2fa sees omnibase's User today: its secret
 * (user.secret), SHA1, 30 seconds, 6 digits (User::TOTP_TIMEOUT,
 * User::TOTP_LENGTH), its identifier as the label. Loaded only where
 * scheb/2fa is installed.
 */
final class SchebUser implements TwoFactorInterface
{
    public function __construct(public ?string $secret, public string $identifier = 'ringo')
    {
    }

    public function isTotpAuthenticationEnabled(): bool
    {
        return (bool) $this->secret;
    }

    public function getTotpAuthenticationUsername(): string
    {
        return $this->identifier;
    }

    public function getTotpAuthenticationConfiguration(): ?TotpConfigurationInterface
    {
        return null === $this->secret ? null : new TotpConfiguration($this->secret, TotpConfiguration::ALGORITHM_SHA1, 30, 6);
    }
}
