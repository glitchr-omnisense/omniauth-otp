<?php

namespace Omniauth\Totp\Contract;

/*
 * Omniauth\Totp\Contract\SecretBox is now Omniauth\Otp\Contract\SecretBox: omniauth/totp was renamed
 * omniauth/otp (TOTP today, HOTP possible), which replaces it.
 * The former name is an alias of the new class for one release.
 *
 * @deprecated use Omniauth\Otp\Contract\SecretBox (composer require omniauth/otp)
 */
@trigger_error('Omniauth\Totp\Contract\SecretBox is deprecated: use Omniauth\Otp\Contract\SecretBox (omniauth/otp).', \E_USER_DEPRECATED);
class_alias(\Omniauth\Otp\Contract\SecretBox::class, SecretBox::class);
