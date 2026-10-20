<?php

/*
 * omniauth/totp in plain PHP: no bundle, no container, no framework. The
 * conductor built by hand on the in-memory stores; an account sets up its
 * authenticator application (a secret, its otpauth:// address, a first
 * code), then signs in with a password and a code; the same code again; the
 * next period's code. Prints what happened and every class and file PHP
 * loaded, as JSON. Argument: the autoloader.
 */

use Omniauth\ArrayState;
use Omniauth\Context;
use Omniauth\Factor;
use Omniauth\Method\Methods;
use Omniauth\Omniauth;
use Omniauth\Password\PasswordMethod;
use Omniauth\Result;
use Omniauth\Testing\ArrayCache;
use Omniauth\Testing\FixedClock;
use Omniauth\Testing\InMemoryStore;
use Omniauth\Testing\TestAccount;
use Omniauth\Totp\CacheUsedSteps;
use Omniauth\Totp\Testing\AuthenticatorApp;
use Omniauth\Totp\TotpMethod;
use Symfony\Component\PasswordHasher\Hasher\NativePasswordHasher;

require $autoload = $argv[1];

$clock = new FixedClock('2026-10-20 12:00:10 UTC');
$hasher = new NativePasswordHasher(cost: 4);
$store = new InMemoryStore($ringo = new TestAccount('1', 'ringo', 'ringo@example.org', $hasher->hash('yellow-submarine')));
$session = [];
$omniauth = new Omniauth($store, new Methods([
    new PasswordMethod($store, $store, $hasher),
    new TotpMethod($store, $store->totpSecrets(), new CacheUsedSteps(new ArrayCache($clock)), clock: $clock),
]), new ArrayState($session), clock: $clock);
$context = new Context('https://example.org', 'example.org', '203.0.113.7');
$seen = static fn (Result $r) => ['status' => $r->status->value, 'passed' => array_map(fn ($f) => $f->value, $r->passed), 'offered' => array_map(fn ($f) => $f->value, $r->offered), 'failure' => $r->failure?->value, 'reason' => $r->reason];

$enrolment = $omniauth->enrol(Factor::Totp, $ringo);
$challenge = $enrolment->begin($context);
$app = AuthenticatorApp::scan($challenge->data['uri'], $clock);
$report['enrolment'] = [$challenge->kind, $challenge->data['uri'] === 'otpauth://totp/ringo?secret='.$challenge->data['secret'], $enrolment->confirm($context, ['code' => $app->code()])->isDone(), $ringo->totpSecret === $challenge->data['secret']];

$clock->advance(30);
$report['sign-in'][] = $seen($omniauth->verify('password', $context, ['identifier' => 'ringo', 'password' => 'yellow-submarine']));
$report['sign-in'][] = $seen($omniauth->verify('totp', $context, ['code' => $code = $app->code()]));
$omniauth->verify('password', $context, ['identifier' => 'ringo', 'password' => 'yellow-submarine']);
$report['again'] = $seen($omniauth->verify('totp', $context, ['code' => $code]));
$clock->advance(30);
$report['next'] = $seen($omniauth->verify('totp', $context, ['code' => $app->code()]));

$report['loaded'] = [
    'symbols' => [...get_declared_classes(), ...get_declared_interfaces(), ...get_declared_traits()],
    'files' => array_map('realpath', get_included_files()),
    'eager' => array_map('realpath', array_values(is_file($files = dirname($autoload).'/composer/autoload_files.php') ? require $files : [])),
];

echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), "\n";
