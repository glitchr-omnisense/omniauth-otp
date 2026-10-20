<?php

namespace Omniauth\Totp\Contract;

/**
 * The seam for the secrets at rest (Marco's decision QA5, 2026-10-20: the
 * TOTP secret encrypted with sodium, its key in the secrets vault, in a step
 * of its own). omniauth/totp ships no implementation yet: SealedTotpSecrets
 * wraps the application's TotpSecrets store with a box when there is one, and
 * TotpMethod never knows.
 */
interface SecretBox
{
    /** What the store keeps for this base32 secret. */
    public function seal(#[\SensitiveParameter] string $secret): string;

    /**
     * The base32 secret of what the store keeps. A box must read back the
     * secrets kept before it existed (in clear) until every row is sealed:
     * it tells them apart (a prefix, a version byte) and returns them as
     * they are.
     */
    public function open(#[\SensitiveParameter] string $stored): string;
}
