<?php

namespace Omniauth\Totp;

/*
 * Omniauth\Totp\TotpMethod is now Omniauth\Otp\TotpMethod: omniauth/totp was renamed
 * omniauth/otp (TOTP today, HOTP possible), which replaces it.
 * The former name is an alias of the new class for one release.
 *
 * @deprecated use Omniauth\Otp\TotpMethod (composer require omniauth/otp)
 */
@trigger_error('Omniauth\Totp\TotpMethod is deprecated: use Omniauth\Otp\TotpMethod (omniauth/otp).', \E_USER_DEPRECATED);
class_alias(\Omniauth\Otp\TotpMethod::class, TotpMethod::class);
