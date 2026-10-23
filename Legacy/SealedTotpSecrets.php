<?php

namespace Omniauth\Totp;

/*
 * Omniauth\Totp\SealedTotpSecrets is now Omniauth\Otp\SealedTotpSecrets: omniauth/totp was renamed
 * omniauth/otp (TOTP today, HOTP possible), which replaces it.
 * The former name is an alias of the new class for one release.
 *
 * @deprecated use Omniauth\Otp\SealedTotpSecrets (composer require omniauth/otp)
 */
@trigger_error('Omniauth\Totp\SealedTotpSecrets is deprecated: use Omniauth\Otp\SealedTotpSecrets (omniauth/otp).', \E_USER_DEPRECATED);
class_alias(\Omniauth\Otp\SealedTotpSecrets::class, SealedTotpSecrets::class);
