<?php

namespace Omniauth\Otp;

use Omniauth\Otp\Contract\SecretBox;
use Omniauth\Otp\Exception\UnreadableSecret;

/**
 * The TOTP secrets sealed at rest with libsodium's secretbox (XSalsa20 and
 * Poly1305: encrypted and authenticated) under one 32-byte key - Marco's
 * decision QA5. What the store keeps:
 *
 *     otp:v1:<base64url, unpadded, of the 24-byte nonce then the box>
 *
 * 130 characters for a 52-character secret (scheb/2fa's and TotpMethod's):
 * omnibase's user.secret (VARCHAR 255) holds it as it is. The prefix names the
 * format and its version; a base32 secret (A-Z, 2-7, =) never starts with it,
 * so open() tells a sealed secret from one kept in clear before the box and
 * returns the latter as it is, until every row is sealed; seal() leaves a
 * sealed value as it is (a rewrite of the rows runs twice harmlessly).
 *
 * The key never lives in a file of the application's repository: the host
 * reads it from its secrets vault or its environment (omniauth.yaml's
 * totp.secret_key, config/omniauth.php's), base64 (fromBase64()), and both
 * hosts of one database share it. Key rotation: docs/otp.md.
 */
final class SodiumSecretBox implements SecretBox
{
    public const PREFIX = 'otp:v1:';

    private readonly string $key;

    /** @param string $key the 32 raw bytes of the key */
    public function __construct(#[\SensitiveParameter] string $key)
    {
        if (\SODIUM_CRYPTO_SECRETBOX_KEYBYTES !== \strlen($key)) {
            throw new \InvalidArgumentException(\sprintf('A secret box key is %d bytes (%d given).', \SODIUM_CRYPTO_SECRETBOX_KEYBYTES, \strlen($key)));
        }
        $this->key = $key;
    }

    /** From the key as a host keeps it: base64 (standard or URL-safe, padded or not) of 32 bytes. */
    public static function fromBase64(#[\SensitiveParameter] string $key): self
    {
        $bytes = base64_decode(strtr(trim($key), '-_', '+/'), true);
        if (false === $bytes) {
            throw new \InvalidArgumentException('A secret box key is given in base64.');
        }

        return new self($bytes);
    }

    /** A new key, in base64: what goes into the vault (php -r "require 'vendor/autoload.php'; echo Omniauth\Otp\SodiumSecretBox::generateKey();"). */
    public static function generateKey(): string
    {
        return base64_encode(sodium_crypto_secretbox_keygen());
    }

    /** Whether a stored value is sealed (by this format), without opening it. */
    public static function isSealed(string $stored): bool
    {
        return str_starts_with($stored, self::PREFIX);
    }

    public function seal(#[\SensitiveParameter] string $secret): string
    {
        if (self::isSealed($secret)) {
            return $secret;
        }
        $nonce = random_bytes(\SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

        return self::PREFIX.sodium_bin2base64($nonce.sodium_crypto_secretbox($secret, $nonce, $this->key), \SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }

    /** @throws UnreadableSecret a sealed value that does not open under this key */
    public function open(#[\SensitiveParameter] string $stored): string
    {
        if (!self::isSealed($stored)) {
            return $stored;
        }
        try {
            $bytes = sodium_base642bin(substr($stored, \strlen(self::PREFIX)), \SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        } catch (\SodiumException) {
            throw new UnreadableSecret('A sealed TOTP secret is not readable base64.');
        }
        if (\strlen($bytes) <= \SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + \SODIUM_CRYPTO_SECRETBOX_MACBYTES) {
            throw new UnreadableSecret('A sealed TOTP secret is too short.');
        }
        $secret = sodium_crypto_secretbox_open(substr($bytes, \SODIUM_CRYPTO_SECRETBOX_NONCEBYTES), substr($bytes, 0, \SODIUM_CRYPTO_SECRETBOX_NONCEBYTES), $this->key);
        if (false === $secret) {
            throw new UnreadableSecret('A sealed TOTP secret does not open with this key: sealed under another key, or altered.');
        }

        return $secret;
    }
}
