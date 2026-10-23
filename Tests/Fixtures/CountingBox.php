<?php

namespace Omniauth\Otp\Tests\Fixtures;

use Omniauth\Otp\Contract\SecretBox;

/** A box that counts what it opens. */
final class CountingBox implements SecretBox
{
    public int $opened = 0;

    public function __construct(private readonly SecretBox $box)
    {
    }

    public function seal(#[\SensitiveParameter] string $secret): string
    {
        return $this->box->seal($secret);
    }

    public function open(#[\SensitiveParameter] string $stored): string
    {
        ++$this->opened;

        return $this->box->open($stored);
    }
}
