<?php

namespace Omniauth\Totp\Testing;

/*
 * Omniauth\Totp\Testing\AuthenticatorApp is now Omniauth\Otp\Testing\AuthenticatorApp: omniauth/totp was renamed
 * omniauth/otp (TOTP today, HOTP possible), which replaces it.
 * The former name is an alias of the new class for one release.
 *
 * @deprecated use Omniauth\Otp\Testing\AuthenticatorApp (composer require omniauth/otp)
 */
@trigger_error('Omniauth\Totp\Testing\AuthenticatorApp is deprecated: use Omniauth\Otp\Testing\AuthenticatorApp (omniauth/otp).', \E_USER_DEPRECATED);
class_alias(\Omniauth\Otp\Testing\AuthenticatorApp::class, AuthenticatorApp::class);
