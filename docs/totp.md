---
title: The method
order: 2
---

# The method

```php
new TotpMethod(
    accounts: $accounts,                 // Omniauth\Contract\Accounts: the handle, the identifier (the QR code's label)
    secrets: $secrets,                   // Omniauth\Contract\TotpSecrets (omnibase: user.secret)
    used: new CacheUsedSteps($pool),     // Contract\UsedSteps: a code once
    leeway: 0,                           // seconds before and after a period, as scheb's `leeway`
    period: 30, digits: 6, algorithm: 'sha1',   // scheb/2fa's, as omnibase's User gives them
    issuer: null, server: null,          // scheb's `issuer` and `server_name`: the QR code's label
    clock: null,                         // PSR-20; the system's by default
);
```

A second factor: `EnrolledSecondFactors` asks it after a password, a link or an identity provider
of an account that has a secret (`enrolled()`), and offers the backup codes beside it.

## Signing in

`$omniauth->verify('totp', $context, ['code' => '123 456'])`, once a first factor passed. Spaces
are ignored. otphp verifies the code at this moment within the leeway, exactly as scheb/2fa calls
it; then the code's time step is claimed for the account (`UsedSteps::claim()`): a step already
claimed, or an earlier one, is refused.

| Failure | Reason | When |
|---|---|---|
| `bad-code` | - | not the code of the moment (or empty) |
| | `replayed` | the right code, already used - or older than the last one used |
| | `unreadable-secret` | the stored secret is not base32 |
| `not-enrolled` | - | the account has no secret |

## Setting it up, from the settings

| Step | Call | Gives |
|---|---|---|
| begin | `$omniauth->enrol(Factor::Totp, $account)->begin($context)` | `Challenge::none(['secret' => ..., 'uri' => 'otpauth://totp/ringo?secret=...'])`; the secret waits in the enrolment (the session), not in the store |
| confirm | `->confirm($context, ['code' => ...])` | `Enrolled::done()` and `TotpSecrets::enable()`; a wrong code keeps the secret waiting |

The page draws the QR code of `uri` (omnibase keeps endroid/qr-code for that) and may show
`secret` for typing in. `$method->uri($account)` gives the address of the account's own secret
(today's `qr_code_totp` route).

## Turning it off

`$omniauth->revoke(Factor::Totp, $account)`: `TotpSecrets::disable()`, and the conductor makes the
trusted devices fall back.

## Sealed secrets (QA5)

```php
$secrets = new SealedTotpSecrets($store, $box);   // $box: Contract\SecretBox - seal(), open()
```

The box opens the secrets kept before it in clear as they are, until every row is sealed. No box
ships yet: encryption at rest is a step of its own.
