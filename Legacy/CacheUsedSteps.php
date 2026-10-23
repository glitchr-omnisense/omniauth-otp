<?php

namespace Omniauth\Totp;

/*
 * Omniauth\Totp\CacheUsedSteps is now Omniauth\Otp\CacheUsedSteps: omniauth/totp was renamed
 * omniauth/otp (TOTP today, HOTP possible), which replaces it.
 * The former name is an alias of the new class for one release.
 *
 * @deprecated use Omniauth\Otp\CacheUsedSteps (composer require omniauth/otp)
 */
@trigger_error('Omniauth\Totp\CacheUsedSteps is deprecated: use Omniauth\Otp\CacheUsedSteps (omniauth/otp).', \E_USER_DEPRECATED);
class_alias(\Omniauth\Otp\CacheUsedSteps::class, CacheUsedSteps::class);
