<?php

namespace Omniauth\Totp;

use Omniauth\Contract\TotpSecrets;
use Omniauth\Totp\Contract\SecretBox;

/**
 * An application's TotpSecrets store with its secrets sealed by a box: what
 * the store keeps is the box's, what TotpMethod reads is the base32 secret.
 * The seam QA5 asked for - encryption at rest comes in a step of its own,
 * with a box (sodium, the key in the secrets vault) and the rows rewritten.
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

    public function enable(object $account, #[\SensitiveParameter] string $secret): void
    {
        $this->store->enable($account, $this->box->seal($secret));
    }

    public function disable(object $account): void
    {
        $this->store->disable($account);
    }
}
