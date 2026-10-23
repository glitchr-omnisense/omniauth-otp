<?php

namespace Omniauth\Otp;

use Omniauth\Contract\TotpSecrets;
use Omniauth\Otp\Contract\SecretBox;

/**
 * An application's TotpSecrets store with its secrets sealed by a box
 * (SodiumSecretBox: Marco's decision QA5): what the store keeps is the box's,
 * what TotpMethod reads is the base32 secret. A secret is opened only when a
 * code is verified or the enrolment's QR code is drawn (secret()); whether an
 * account has one is read without opening it (has()). A secret that does not
 * open throws (Exception\UnreadableSecret): never "no secret", which would let
 * the account in without its second factor.
 */
final class SealedTotpSecrets implements TotpSecrets
{
    public function __construct(
        private readonly TotpSecrets $store,
        private readonly SecretBox $box,
    ) {
    }

    public function secret(object $account): ?string
    {
        $stored = $this->store->secret($account);

        return null === $stored || '' === $stored ? $stored : $this->box->open($stored);
    }

    /** Whether the account has a secret, without opening it. */
    public function has(object $account): bool
    {
        return '' !== (string) $this->store->secret($account);
    }

    public function enable(object $account, #[\SensitiveParameter] string $secret): void
    {
        $this->store->enable($account, $this->box->seal($secret));
    }

    public function disable(object $account): void
    {
        $this->store->disable($account);
    }
}
