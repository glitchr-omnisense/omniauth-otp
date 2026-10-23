<?php

namespace Omniauth\Otp\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** omniauth/totp's names, aliases of omniauth/otp's classes for one release. */
final class FormerNamesTest extends TestCase
{
    /** @return iterable<string, array{string}> */
    public static function classes(): iterable
    {
        foreach (['TotpMethod', 'CacheUsedSteps', 'SealedTotpSecrets', 'Contract\\SecretBox', 'Contract\\UsedSteps', 'Testing\\AuthenticatorApp'] as $class) {
            yield $class => [$class];
        }
    }

    #[DataProvider('classes')]
    public function testEachFormerNameIsTheNewClass(string $class): void
    {
        $former = 'Omniauth\\Totp\\'.$class;
        self::assertTrue(@class_exists($former) || @interface_exists($former), $former);
        self::assertSame('Omniauth\\Otp\\'.$class, (new \ReflectionClass($former))->getName(), $former);
    }

    public function testEachFormerNameSaysItIsDeprecated(): void
    {
        $files = glob(\dirname(__DIR__).'/Legacy/{,*/}*.php', \GLOB_BRACE) ?: [];
        self::assertCount(6, $files);
        foreach ($files as $file) {
            self::assertMatchesRegularExpression('~@trigger_error\(\'Omniauth\\\\Totp\\\\[\w\\\\]+ is deprecated: use Omniauth\\\\Otp\\\\[\w\\\\]+ \(omniauth/otp\)\.\', \\\\E_USER_DEPRECATED\);~', (string) file_get_contents($file), $file);
        }
    }
}
