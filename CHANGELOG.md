# Changelog

Every version of omniauth/otp, newest first ([Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
[Semantic Versioning](https://semver.org/)). A release's notes are its section here: the release
workflow refuses a tag without one.

## [Unreleased]

## [1.0.0] - 2026-11-13

The first stable version. It requires `omnisense/omniauth` `^1.0` with no stability flag, so `composer require omniauth/otp` installs it in a project with Composer's default minimum-stability; the 1.x series follows semantic versioning. A tag `vX.Y.Z` is released by `.github/workflows/release.yml` once the package's CI passes on it.

Omniauth's one-time passwords over spomky-labs/otphp, under any PHP host - authenticator applications (TOTP; HOTP possible): the second factor, its enrolment (a secret and its otpauth:// address) and its revocation, with scheb/2fa's parameters (SHA1, 30 s, 6 digits, the same leeway and provisioning address) so the secrets an application keeps today go on working, a code accepted once only, and the secrets sealed at rest with libsodium (SodiumSecretBox, the key in the host's vault; the ones kept in clear read until rewritten). Formerly omniauth/totp, which it replaces (the Omniauth\Totp\ names stay aliases for one release).
