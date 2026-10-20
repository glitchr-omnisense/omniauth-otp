# omniauth/totp

Authenticator applications (TOTP, RFC 6238) for
[omniscient/omniauth](https://github.com/glitchr-studio/omniauth), **under any PHP host**, over
spomky-labs/otphp - the library scheb/2fa verifies with, on the same parameters, so the secrets an
application keeps today go on working and a code scheb accepts is accepted here. Once: the same
code is refused the second time.

```php
use Omniauth\{ArrayState, Context, Factor, Omniauth};
use Omniauth\Method\Methods;
use Omniauth\Password\PasswordMethod;
use Omniauth\Totp\{CacheUsedSteps, TotpMethod};

$omniauth = new Omniauth(
    accounts: $accounts,                                   // your accounts, behind Omniauth\Contract\Accounts
    methods: new Methods([
        new PasswordMethod($accounts, $passwords),
        new TotpMethod($accounts, $secrets, new CacheUsedSteps($pool)),   // $secrets: Contract\TotpSecrets (user.secret); $pool: PSR-6 or PSR-16
    ]),
    state: new ArrayState($_SESSION),
);
$context = new Context(origin: 'https://example.org', host: 'example.org', ip: $_SERVER['REMOTE_ADDR']);

$result = $omniauth->verify('password', $context, ['identifier' => 'ringo@example.org', 'password' => '...']);
// SecondFactorRequired, $result->offered === [Factor::Totp]
$result = $omniauth->verify('totp', $context, ['code' => '481 516']);
// Authenticated, $result->passed === [Factor::Password, Factor::Totp]; the same code again: bad-code, "replayed"

$enrolment = $omniauth->enrol(Factor::Totp, $account);    // from the settings
$challenge = $enrolment->begin($context);                  // $challenge->data: 'secret', 'uri' (otpauth://, for the QR code)
$enrolment->confirm($context, ['code' => '123456']);       // a first code: the secret is kept
```

It requires omniscient/omniauth, spomky-labs/otphp ^11.3 (and paragonie's constant-time encoding,
which otphp requires) and the PSR cache and clock interfaces. No framework.

## The same as scheb/2fa

Every site sets scheb/2fa's TOTP the same way, and omnibase's `User` gives it the same
configuration; `TotpMethod`'s defaults are those:

| | scheb/2fa today | `TotpMethod` |
|---|---|---|
| algorithm, period, digits | `User::getTotpAuthenticationConfiguration()`: SHA1, 30 s, 6 | `ALGORITHM`, `PERIOD`, `DIGITS` |
| leeway | `scheb_two_factor.totp.leeway: 0` on all 25 sites | `LEEWAY` = 0 (seconds, as scheb's) |
| verification | `TOTP::verify($code, null, $leeway)`, spaces stripped | the same call |
| secret | `TotpAuthenticator::generateSecret()`: 32 bytes, base32 upper, unpadded | `TotpMethod::secret()`: the same |
| QR code's address | `getQRContent()`: label = the identifier (`@` server name when set), issuer when set | `uri()`: the same address |
| the same code twice | accepted | **refused** (`bad-code`, reason `replayed`) |

## A code once

`Contract\UsedSteps` remembers, per account, the last time step whose code was accepted: a code of
that step or an earlier one is refused, inside the leeway too (RFC 6238 §5.2). `CacheUsedSteps`
keeps it in any PSR-6 pool or PSR-16 cache - the host's cache pool - for as long as the code could
still verify. Read then written, not atomic: two requests with the same code at the same instant may
both pass (the conductor's throttle, five codes per 15 minutes per account, bounds the rest).

## The secrets at rest: the seam (QA5)

Marco's decision QA5 encrypts the TOTP secrets (sodium, the key in the secrets vault) in a step of
its own, after lesringostars switches. The seam is here: `Contract\SecretBox` (`seal()`, `open()`)
and `SealedTotpSecrets`, which wraps the application's `TotpSecrets` store with a box - the method
never knows. No box ships yet; until then secrets go through the store as they are (base32, in
clear, as today).

## The shape

| | |
|---|---|
| `TotpMethod` | a second factor (`SecondFactor`, `Enrolling`, `Revocable`): `verify()`, `enrolBegin()`/`enrolConfirm()`, `revoke()`, `uri()`, `code()`, `secret()` |
| `Contract\UsedSteps`, `CacheUsedSteps` | a code once |
| `Contract\SecretBox`, `SealedTotpSecrets` | the seam for sealed secrets |
| `Testing\AuthenticatorApp` | the person's phone: scans the enrolment's `uri`, shows the code of the moment |

The store of the secrets is omniauth's `Omniauth\Contract\TotpSecrets` (omnibase: `user.secret`,
step AU4); `Omniauth\Testing\InMemoryTotpSecrets` in tests.

## Documentation

- [Installation, in plain PHP](docs/installation.md)
- [The method](docs/totp.md)

## Verified, and not

- Verified (omniauth's harness, `docker compose run --rm omniauth test` in the core's `docker/`, PHP
  8.4, scheb/2fa 8.6.1 installed beside; every file linted on PHP 8.2):
  - RFC 6238's SHA1 vectors; a password then a code, through the conductor; an account without a
    secret asked nothing; a code once - the same code in its period refused, the next period's
    accepted, the same code good for another account, an earlier code inside the leeway refused
    after a later one; the leeway in scheb's seconds; wrong and empty codes; five wrong codes and
    the account throttled whatever the address; the enrolment (secret, address, a wrong then a good
    first code, the secret kept, its code used up), an enrolment never begun, the revocation (the
    trusted devices fall back); the address with a server name and an issuer; a sealed store;
  - **against scheb/2fa itself**: a secret scheb drew and a code scheb accepts (it accepts it twice)
    sign in here once, and the second time are refused; second by second across two period
    boundaries, every code of the periods around and a wrong one, for leeways 0, 5 and 29, scheb's
    `checkCode()` and a first use here answer the same (more than 300 comparisons each); the QR
    code's address equal to `getQRContent()` with and without a server name and an issuer; codes and
    an address scheb wrote, recorded, equal here without scheb;
  - `docs/installation.md` run as written; in plain PHP (`BareTest`), an enrolment and a sign-in by
    hand loading nothing but omniauth, otphp, paragonie's encoding, the PSR interfaces and
    symfony/password-hasher - no class of a framework, of scheb/2fa or of an application.
- Not verified: a real phone's application (at AU7, in Chrome, against the site); the host's store
  (`Base\Auth\UserTotpSecrets`, AU4); concurrent tries of the same code against `CacheUsedSteps`;
  sealed secrets (no box yet: QA5's own step).

## Licence

MIT.
