# omniauth/otp

One-time passwords - authenticator applications (TOTP, RFC 6238) - as a second factor of
[omnisense/omniauth](https://github.com/glitchr-omnisense/omniauth), under any PHP host, over
spomky-labs/otphp: the library scheb/2fa verifies with, on the same parameters, so the secrets an
application keeps today go on working and a code scheb/2fa accepts is accepted here - once: the
same code is refused the second time. The secrets can be sealed at rest with libsodium (Marco's
decision QA5). It calls no service: everything happens between the server and the person's phone.

```php
new TotpMethod($accounts, new SealedTotpSecrets($secrets, SodiumSecretBox::fromBase64($key)), new CacheUsedSteps($pool));
```

This package was **omniauth/totp** until 2026-10-23 (renamed: TOTP today, HOTP possible). It
`replace`s omniauth/totp, and the former namespace `Omniauth\Totp\` stays an alias of
`Omniauth\Otp\` for one release (`Legacy/`: each former class name loads the new class, with a
deprecation notice). The factor keeps its name, `totp` (`Factor::Totp`).

## Installation

```sh
composer require omnisense/omniauth omniauth/otp
```

Requires PHP 8.2 with `ext-sodium` (bundled with PHP), `omnisense/omniauth` (1.x),
`spomky-labs/otphp` (^11.3), `paragonie/constant_time_encoding` (^2.6 or ^3.0), `psr/cache`,
`psr/simple-cache` and `psr/clock`. No framework. Under omnibridge/symfony and omnibridge/laravel,
the `totp` key turns it on ([Hosts](#hosts)).

## Options

`new TotpMethod(...)`:

| Argument | Type | Default | |
|---|---|---|---|
| `accounts` | `Omniauth\Contract\Accounts` | required | the handle (the steps used are per account) and the identifier (the QR address's label) |
| `secrets` | `Omniauth\Contract\TotpSecrets` | required | the base32 secrets (omnibase: `user.secret`); a `SealedTotpSecrets` to seal them |
| `used` | `Contract\UsedSteps` | required | the steps already used: `CacheUsedSteps` on a cache |
| `leeway` | `int`, 0 to `period - 1` | `0` (`TotpMethod::LEEWAY`) | seconds a code is accepted before and after its period (scheb/2fa's `leeway`) |
| `period` | `int`, at least 1 | `30` (`PERIOD`) | |
| `digits` | `int`, 6 to 10 | `6` (`DIGITS`) | |
| `algorithm` | `string` | `sha1` (`ALGORITHM`) | otphp's digest name |
| `issuer` | `?string` | `null` | the QR address's issuer (scheb's `issuer`) |
| `server` | `?string` | `null` | appended to the label after `@` (scheb's `server_name`) |
| `clock` | `?Psr\Clock\ClockInterface` | `null`: `SystemClock` | |

Values outside those ranges throw an `InvalidArgumentException` from the constructor.

| Class | Constructor | |
|---|---|---|
| `CacheUsedSteps` | `(CacheItemPoolInterface\|CacheInterface $cache, string $prefix = 'omniauth.totp.')` | the last step each account used, in any PSR-6 pool or PSR-16 cache, keyed by the handle's SHA-256 |
| `SodiumSecretBox` | `(string $key)`: 32 raw bytes; `SodiumSecretBox::fromBase64($key)`: base64, standard or URL-safe, padded or not | `generateKey()` draws a key (base64), `isSealed($stored)`, `seal()`, `open()`; `PREFIX` is `otp:v1:` |
| `SealedTotpSecrets` | `(TotpSecrets $store, Contract\SecretBox $box)` | the store with its secrets sealed: `secret()` opens, `has()` does not, `enable()` seals |

## Capabilities

| | |
|---|---|
| a second factor (`Method\SecondFactor`): `enrolled()` | yes: the account has a secret (`SealedTotpSecrets::has()` without opening it) |
| `begin()` (`Method\Challenging`) | no: the code is on the phone, nothing to send |
| set up from the settings (`Method\Enrolling`) | yes: a secret and its `otpauth://` address, then a first code |
| turned off (`Method\Revocable`) | yes: `TotpSecrets::disable()` |
| a code once (RFC 6238 §5.2) | yes, and none older than the last one used |
| scheb/2fa's parameters, secrets and QR address | yes ([The same as scheb/2fa](#the-same-as-scheb2fa)) |
| HOTP (counter-based codes) | no |
| secrets sealed at rest | yes, with `SealedTotpSecrets` and `SodiumSecretBox` |

`TotpMethod` also gives `uri($account, ?string $secret = null)` (the `otpauth://` address of a
secret, or of the account's own: the settings' QR code; null when it has none), `code($secret,
?int $timestamp = null)` (the code of a moment) and `TotpMethod::secret()` (a new secret: 32 random
bytes, base32, upper case, unpadded - 52 characters, as scheb/2fa draws them).

### The same as scheb/2fa

| | scheb/2fa | `TotpMethod` |
|---|---|---|
| algorithm, period, digits | omnibase's `User::getTotpAuthenticationConfiguration()`: SHA1, 30 s, 6 | `ALGORITHM`, `PERIOD`, `DIGITS` |
| leeway | `scheb_two_factor.totp.leeway: 0` | `LEEWAY` = 0 (seconds, as scheb's) |
| verification | `TOTP::verify($code, null, $leeway)`, spaces stripped | the same call |
| secret | `TotpAuthenticator::generateSecret()`: 32 bytes, base32 upper, unpadded | `TotpMethod::secret()` |
| QR code's address | `getQRContent()`: label the identifier (`@` server name when set), issuer when set | `uri()`: the same address |
| the same code twice | accepted | refused (`bad-code`, reason `replayed`) |

## Hosts

| | omnibridge/symfony (`omniauth.yaml`) | omnibridge/laravel (`config/omniauth.php`) |
|---|---|---|
| on | `totp: ~` | `'totp' => [...]` |
| `leeway`, `period`, `digits`, `issuer`, `server_name` | `totp.*`, the defaults above | `totp.*`, the same |
| the steps used | `CacheUsedSteps` on `throttle.pool` | `CacheUsedSteps` on the throttle's store or pool |
| `secret_key` | `totp.secret_key`: a lazy `SodiumSecretBox`, `SealedTotpSecrets` decorating the `totp_secrets` store | `totp.secret_key`: the `TotpSecrets` binding wrapped the same way |

The two hosts of one database must hold the same key (`OMNIAUTH_TOTP_KEY` on omnibase sites).
The second factor's page names this factor `totp`, as scheb/2fa did.

## Errors

The failures a sign-in or an enrolment answers are listed in [The method](otp.md#signing-in):
`bad-code` (reasons `replayed`, `unreadable-secret`), `not-enrolled`, `expired`. The exceptions:

| Exception | When |
|---|---|
| `Exception\UnreadableSecret` (an `OmniauthException`, `\RuntimeException`) | a sealed secret that does not open: another key, an altered, truncated or non-base64 value. Its message names neither the key nor the secret |
| `\InvalidArgumentException` | `TotpMethod` with a period, leeway or digits out of range; a box key that is not 32 bytes or not base64; `AuthenticatorApp::scan()` of an address that is not TOTP |

## Verified, and not

Run in omniauth's harness on 2026-10-25 (PHP 8.4, scheb/2fa 8.6 installed beside): omniauth/otp's
47 tests green. They cover RFC 6238's SHA1 vectors; a password then a code through the conductor; a
code once (the same code in its period refused, the next period's accepted, the same code good for
another account, an earlier code inside the leeway refused after a later one); the leeway in
scheb's seconds; five wrong codes and the account throttled whatever the address; the enrolment and
the revocation; the address with a server name and an issuer; **against scheb/2fa itself**, second
by second across two period boundaries for leeways 0, 5 and 29, scheb's `checkCode()` and a first
use here answer the same, and the QR address equals `getQRContent()`; the sealed secrets (format,
nonce, another key, altered and truncated values refused with `UnreadableSecret`, a sign-in and an
enrolment on a sealed store); `docs/installation.md` run as written; in plain PHP (`BareTest`),
nothing loaded but omniauth, otphp, paragonie's encoding, the PSR interfaces and
symfony/password-hasher; the former `Omniauth\Totp\` names.

Not verified: a real phone's application against a site; concurrent tries of the same code against
`CacheUsedSteps` (read then written, not atomic: two requests with the same code at the same
instant may both pass; the throttle, five codes per 15 minutes per account, bounds the rest).
