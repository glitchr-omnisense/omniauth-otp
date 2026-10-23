<?php

namespace Omniauth\Otp\Exception;

use Omniauth\Exception\OmniauthException;

/**
 * A sealed secret that does not open: sealed under another key (a key
 * rotated without its rows, a host on the wrong key), or altered. Never
 * answered as "no secret": an account would then sign in without the second
 * factor it set up. The message names no key and no secret.
 */
final class UnreadableSecret extends \RuntimeException implements OmniauthException
{
}
