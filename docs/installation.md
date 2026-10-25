---
title: Installation
order: 10
---

## Installation

```sh
composer require omniscient/omniauth omniauth/otp
```

It requires omniscient/omniauth, spomky-labs/otphp (the library scheb/2fa verifies with) and the
PSR cache and clock interfaces. No framework: the secrets stay in your table, behind omniauth's
`Contract\TotpSecrets`; the steps already used, in any PSR-6 pool or PSR-16 cache.

The whole thing by hand - the in-memory stores of `Omniauth\Testing` stand in for yours, and
`Omniauth\Otp\Testing\AuthenticatorApp` for the person's phone:

```php
<?php

require 'vendor/autoload.php';

use Omniauth\ArrayState;
use Omniauth\Context;
use Omniauth\Factor;
use Omniauth\Method\Methods;
use Omniauth\Omniauth;
use Omniauth\Password\PasswordMethod;
use Omniauth\Testing\ArrayCache;
use Omniauth\Testing\FixedClock;
use Omniauth\Testing\InMemoryStore;
use Omniauth\Testing\TestAccount;
use Omniauth\Otp\CacheUsedSteps;
use Omniauth\Otp\Testing\AuthenticatorApp;
use Omniauth\Otp\TotpMethod;
use Symfony\Component\PasswordHasher\Hasher\NativePasswordHasher;

$clock = new FixedClock();                                 // yours: none (the system's); fixed here, the block runs in one go
$hasher = new NativePasswordHasher();
$store = new InMemoryStore($ringo = new TestAccount('42', 'ringo', 'ringo@example.org', $hasher->hash('yellow-submarine')));

$session = [];                                             // $_SESSION, in a real page
$omniauth = new Omniauth(
    accounts: $store,
    methods: new Methods([
        new PasswordMethod($store, $store, $hasher),
        new TotpMethod($store, $store->totpSecrets(), new CacheUsedSteps(new ArrayCache($clock)), clock: $clock),   // your cache pool
    ]),
    state: new ArrayState($session),
    clock: $clock,
);
$context = new Context(origin: 'https://example.org', host: 'example.org', ip: '203.0.113.7');

// From the account's settings: a secret and its address, drawn as a QR code by your page.
$enrolment = $omniauth->enrol(Factor::Totp, $ringo);
$challenge = $enrolment->begin($context);
echo $challenge->data['uri'] === 'otpauth://totp/ringo?secret='.$challenge->data['secret'] ? "otpauth://totp/ringo?secret=...\n" : '';
// otpauth://totp/ringo?secret=...

$phone = AuthenticatorApp::scan($challenge->data['uri'], $clock);
echo $enrolment->confirm($context, ['code' => $phone->code()])->isDone() ? "set up\n" : "not set up\n";
// set up

// Half a minute later: a password, then the code of the moment (the enrolment's is used up).
$clock->advance(30);
$result = $omniauth->verify('password', $context, ['identifier' => 'ringo', 'password' => 'yellow-submarine']);
echo $result->status->value, ': ', $result->offered[0]->value, "\n";
// second-factor-required: totp

$result = $omniauth->verify('totp', $context, ['code' => $phone->code()]);
echo $result->status->value, ' by ', implode(' + ', array_map(fn ($f) => $f->value, $result->passed)), "\n";
// authenticated by password + totp
```

A code is good once: the same code again, even within its 30 seconds, is refused (`bad-code`, reason
`replayed`) - scheb/2fa accepted it again.

The parameters are scheb/2fa's, as every site sets them today: SHA1, 30 seconds, 6 digits,
`leeway: 0` (`TotpMethod::ALGORITHM`, `PERIOD`, `DIGITS`, `LEEWAY`), no server name, no issuer. The
secrets those sites keep (`user.secret`, base32) are read as they are.

Run in omniauth's harness on 2026-10-25 (the block as it is, `Tests/DocsTest.php`), it prints:

```
otpauth://totp/ringo?secret=...
set up
second-factor-required: totp
authenticated by password + totp
```

Next: [the method](otp.md).
