<?php

namespace Omniauth\Totp\Contract;

/*
 * Omniauth\Totp\Contract\UsedSteps is now Omniauth\Otp\Contract\UsedSteps: omniauth/totp was renamed
 * omniauth/otp (TOTP today, HOTP possible), which replaces it.
 * The former name is an alias of the new class for one release.
 *
 * @deprecated use Omniauth\Otp\Contract\UsedSteps (composer require omniauth/otp)
 */
@trigger_error('Omniauth\Totp\Contract\UsedSteps is deprecated: use Omniauth\Otp\Contract\UsedSteps (omniauth/otp).', \E_USER_DEPRECATED);
class_alias(\Omniauth\Otp\Contract\UsedSteps::class, UsedSteps::class);
