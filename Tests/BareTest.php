<?php

namespace Omniauth\Totp\Tests;

use Omniauth\Omniauth;
use Omniauth\Totp\TotpMethod;
use PHPUnit\Framework\TestCase;

/**
 * omniauth/totp with no framework: in PHP processes of their own (this one
 * has loaded PHPUnit), a whole enrolment and sign-in by hand, and every
 * class of the package loaded. Nothing may come from outside but omniauth,
 * otphp and what it requires (paragonie's constant-time encoding), the PSR
 * interfaces and symfony/password-hasher - no class of a framework, of
 * scheb/2fa or of an application, though the harness has them installed.
 */
final class BareTest extends TestCase
{
    private const FOREIGN = '~^(?:Symfony\\\\(?!Component\\\\PasswordHasher\\\\|Polyfill\\\\)|(?:Illuminate|Laravel|Doctrine|Twig|Scheb|Lcobucci|Webauthn|League|Omnibridge|Base|App)\\\\)~';
    private const ALLOWED_FILES = '~/vendor/(?:psr/(?:cache|clock|event-dispatcher|simple-cache)|symfony/password-hasher|spomky-labs/otphp|paragonie/constant_time_encoding|omniscient/omniauth|omniauth/totp|composer)/|/vendor/autoload\.php$~';

    public function testAnEnrolmentAndASignInByHandLoadNothingElse(): void
    {
        $report = self::php([__DIR__.'/Fixtures/bare.php', self::autoload()]);

        self::assertSame(['none', true, true, true], $report['enrolment'], 'a secret, its address, a first code, the secret kept');
        self::assertSame(['second-factor-required', ['totp']], [$report['sign-in'][0]['status'], $report['sign-in'][0]['offered']]);
        self::assertSame(['authenticated', ['password', 'totp']], [$report['sign-in'][1]['status'], $report['sign-in'][1]['passed']]);
        self::assertSame(['failed', 'bad-code', 'replayed'], [$report['again']['status'], $report['again']['failure'], $report['again']['reason']]);
        self::assertSame(['authenticated', ['password', 'totp']], [$report['next']['status'], $report['next']['passed']], 'the next period\'s code');

        self::assertContains(TotpMethod::class, $report['loaded']['symbols']);
        self::assertContains('OTPHP\TOTP', $report['loaded']['symbols']);
        self::assertSame([], self::foreign($report['loaded']['symbols']));
        self::assertSame([], self::outside($report['loaded']['files'], $report['loaded']['eager']));
    }

    public function testEveryClassLoadsWithTheRequiredPackagesAlone(): void
    {
        $report = self::php([__DIR__.'/Fixtures/load-all.php', self::autoload(), \dirname(__DIR__), 'Omniauth\Totp']);

        self::assertContains(TotpMethod::class, $report['loaded']);
        self::assertContains('Omniauth\Totp\Testing\AuthenticatorApp', $report['loaded']);
        self::assertContains('Omniauth\Totp\SealedTotpSecrets', $report['loaded']);
        self::assertSame([], self::foreign($report['symbols']));
        self::assertSame([], self::outside($report['files'], $report['eager']));
    }

    /** The check is not blind: a class of scheb/2fa, once loaded, is seen. */
    public function testTheReportSeesWhatIsLoaded(): void
    {
        $scheb = 'Scheb\TwoFactorBundle\Model\Totp\TotpConfiguration';
        if (!class_exists($scheb)) {
            self::markTestSkipped('scheb/2fa is not installed.');
        }
        $report = self::php([__DIR__.'/Fixtures/load-all.php', self::autoload(), \dirname(__DIR__), 'Omniauth\Totp', $scheb]);

        self::assertContains($scheb, self::foreign($report['symbols']));
        self::assertNotEmpty(preg_grep('~/scheb/~', self::outside($report['files'], $report['eager'])));
    }

    /** @return list<string> */
    private static function foreign(array $symbols): array
    {
        return array_values(preg_grep(self::FOREIGN, $symbols));
    }

    /**
     * The files loaded from outside this package, omniauth's core and otphp
     * - but those Composer includes for every package at start (autoload
     * "files"), which say nothing of what this one uses.
     *
     * @return list<string>
     */
    private static function outside(array $files, array $eager): array
    {
        $roots = [realpath(\dirname(__DIR__)).'/', realpath(\dirname((string) (new \ReflectionClass(Omniauth::class))->getFileName())).'/'];
        $eager = array_map('dirname', array_filter($eager));

        return array_values(array_filter($files, static fn (?string $file) => null !== $file
            && [] === array_filter($roots, static fn (string $root) => str_starts_with($file, $root) && !str_starts_with(substr($file, \strlen($root)), 'vendor/'))
            && !\in_array(\dirname($file), $eager, true)
            && !preg_match(self::ALLOWED_FILES, $file)));
    }

    /** The autoloader that knows this package and its tests. */
    private static function autoload(): string
    {
        foreach (\Composer\Autoload\ClassLoader::getRegisteredLoaders() as $vendor => $loader) {
            if ($loader->findFile(TotpMethod::class) && $loader->findFile(Fixtures\Kit::class)) {
                return $vendor.'/autoload.php';
            }
        }
        self::markTestSkipped('No autoloader knows omniauth/totp\'s tests.');
    }

    /** @return array<string, mixed> */
    private static function php(array $arguments): array
    {
        $process = proc_open([\PHP_BINARY, ...$arguments], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        self::assertIsResource($process);
        $out = (string) stream_get_contents($pipes[1]);
        $err = (string) stream_get_contents($pipes[2]);
        $status = proc_close($process);
        $report = json_decode($out, true);
        self::assertSame(0, $status, $err.$out);
        self::assertIsArray($report, $err.$out);

        return $report;
    }
}
