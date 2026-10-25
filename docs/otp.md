---
title: The method
order: 30
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

A sealed store whose value does not open under the key (another key, an altered row) throws
`Exception\UnreadableSecret` out of `verify()`: the sign-in fails loudly, never as "no secret".
The code's step is claimed only once otphp has verified it; a code that matches at the leeway's
edge claims that step (`intdiv($at, $period)`), and the claim is remembered until the code could
no longer verify (`(step + 1) * period + leeway - now + 1` seconds).

## Setting it up, from the settings

| Step | Call | Gives |
|---|---|---|
| begin | `$omniauth->enrol(Factor::Totp, $account)->begin($context)` | `Challenge::none(['secret' => ..., 'uri' => 'otpauth://totp/ringo?secret=...'])`; the secret waits in the enrolment (the session), not in the store |
| confirm | `->confirm($context, ['code' => ...])` | `Enrolled::done()` and `TotpSecrets::enable()`; a wrong code keeps the secret waiting |

A confirmation with no secret waiting (no `begin()`, or the enrolment's ten minutes gone) is
`Enrolled::failed(expired)`; a first code is claimed like any other, so the same code does not
sign in again right after.

The page draws the QR code of `uri` (omnibase keeps endroid/qr-code for that) and may show
`secret` for typing in. `$method->uri($account)` gives the address of the account's own secret
(today's `qr_code_totp` route).

## Turning it off

`$omniauth->revoke(Factor::Totp, $account)`: `TotpSecrets::disable()`, and the conductor makes the
trusted devices fall back.

## Sealed secrets (QA5)

```php
$secrets = new SealedTotpSecrets($store, SodiumSecretBox::fromBase64($key));   // $key: base64 of 32 bytes, from the vault
new TotpMethod($accounts, $secrets, new CacheUsedSteps($pool));
```

What the store keeps: `otp:v1:` then the base64url (unpadded) of the 24-byte nonce followed by
`sodium_crypto_secretbox($secret, $nonce, $key)` - 130 characters for a 52-character secret. A
value without the prefix is a secret kept in clear before the box: `open()` returns it as it is, so
a site switches on the box first and rewrites its rows after; `seal()` leaves a sealed value as it
is, so the rewrite can run twice. `SealedTotpSecrets::has()` answers whether an account has a secret
without opening it (`TotpMethod::enrolled()` asks it at every sign-in); `secret()` opens it, for
`verify()`, `enrolConfirm()`'s store and `uri()` (the settings' QR code). A value that does not open
throws `Exception\UnreadableSecret`, whose message names neither the key nor the secret.

**The key.** `SodiumSecretBox::generateKey()` draws one (base64). It lives in the host's secrets
vault or environment - for omnibase sites `OMNIAUTH_TOTP_KEY`, read by omnibridge/symfony from
`omniauth.yaml`'s `totp.secret_key` and by omnibridge/laravel from `config/omniauth.php`'s
`totp.secret_key` -, never in a file of the repository: development keeps its own in `.env.local`
(Symfony) or the twin's `.env` (both untracked), the test environment a fixed test key of its own.
Both hosts of one database must hold the same key.

**Rewriting the rows.** Once the box is on, the secrets kept in clear are rewritten by the
application (omnibase sites: a Doctrine migration, up seals each `user.secret` that lacks the prefix,
down opens each that has it), then `SELECT COUNT(*) FROM user WHERE secret IS NOT NULL AND secret
<> '' AND secret NOT LIKE 'otp:v1:%'` is 0.

**Rotating the key.** No code is needed for a rotation, only an order: (1) draw a new key; (2) with
the old key and the new one at hand, rewrite every row - open each sealed value with a box on the old
key, seal it with a box on the new key (a value that already opens with the new key is left; a
secretbox under the wrong key fails to open, it never yields a wrong secret, so the two are told
apart safely); (3) put the new key in the vault of every host of that database at once, and drop the
old one. Between (2) and (3) the hosts must not write new secrets (enrolments) - a short maintenance
window, or a box that tries the new key then the old one, which `SodiumSecretBox` could gain the
day a rotation needs it without a window. A compromised key means rewriting with a new key and,
since a secret read under the old key is known, asking the accounts concerned to enrol again. The
prefix's version (`v1`) names the format, not the key: a new format would be `v2`, read beside `v1`.
