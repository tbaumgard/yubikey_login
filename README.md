# Introduction

YubiKey Login adds local [YubiKey](https://www.yubico.com/products/yubikey-hardware/) [one-time password (OTP) multi-factor authentication](https://developers.yubico.com/OTP/) to a Drupal site for those who can't or don't want to use a separate server dedicated to [YubiCloud-style validation](https://www.yubico.com/products/services-software/yubicloud/).

Some of the features include:

- support for backup codes for users who lose their YubiKeys
- login attempts with a one-time password are rate limited
- backup code attempts are rate limited
- credentials are encrypted using per-user keys derived from passwords
- users are notified of major actions pertaining to their credentials

Be sure to read the *Security Details* section before using this module on a production site.

# Installation

Make sure to install and enable the [Libraries](https://www.drupal.org/project/libraries) module and its dependencies. Then, install the necessary libraries mentioned below. The libraries require [composer](https://getcomposer.org/) to install their dependencies, so make sure it's installed.

PHP 5.6 or later is required.

## php-encryption

Download the [php-encryption](https://github.com/defuse/php-encryption) library and [extract it to one of the library directories](https://www.drupal.org/docs/7/modules/libraries-api/installing-an-external-library-that-is-required-by-a-contributed-module), e.g., `sites/all/libraries/php-encryption`. Then, install its dependencies:

    $ cd sites/all/libraries/php-encryption
    $ composer install --no-dev

The latest version tested and known to work is the v2.0.3 release.

## yubilib

Download the [yubilib](https://github.com/tbaumgard/yubilib) library and [extract it to one of the library directories](https://www.drupal.org/docs/7/modules/libraries-api/installing-an-external-library-that-is-required-by-a-contributed-module), e.g., `sites/all/libraries/yubilib`. Then, install its dependencies:

    $ cd sites/all/libraries/yubilib
    $ composer install --no-dev

The latest version tested and known to work is the v1.0.0 release.

# Using Yubikey Login

The module is incredibly straightforward to use. There are some module settings available from the *YubiKey Login settings* page, accessible from the *Configuration* page. Users can modify their credentials via a contextual link that's shown when viewing or editing an account. Other than that, a *YubiKey OTP* field is added to the login form, and a *Use backup code* page is added to the contextual links shown when requesting a new password. All of these pages include notes and instructions.

If you wish to test the module without having or configuring a YubiKey, the `yubilib` library includes an emulator in the `emulator.php` file. View [its documentation](https://github.com/tbaumgard/yubilib) for more information.

# Security Details

This module hasn't gone through a third-party security audit.

Storing YubiKey one-time password credentials in a Drupal site rather than using a separate server dedicated to YubiCloud-style validation increases the possibility of a third-party attacker gaining access to the credentials since there is a larger attack surface for a Drupal site. There are several mitigations described in the following paragraphs that exist to lessen the impact in the event of an intrusion, but it's important to understand your specific needs and threat model and to decide whether it's a reasonable or unreasonable risk.

Sensitive one-time password credentials are encrypted using the user's password prior to being saved to the database. They are only decrypted when checking if a one-time password is valid or when there is a password change.

The [`php-encryption`](https://github.com/defuse/php-encryption) library is used to derive secure encryption keys from user passwords and to encrypt and decrypt credentials. Additionally, the private identity credential is hashed when a user sets credentials to further mitigate damage in the event that a site is compromised.

Users with one-time password credentials aren't allowed to reset their passwords via email. They are required to use a backup code or to contact a site administrator to regain access.

Backup codes are generated using [`random_bytes()`](https://secure.php.net/manual/en/function.random-bytes.php) and contain 48 bits (6 bytes) of entropy. They are hashed using [`password_hash()`](https://secure.php.net/manual/en/function.password-hash.php) prior to being saved to the database and are verified using [`password_verify()`](https://secure.php.net/manual/en/function.password-verify.php).

Login and backup code attempts are rate limited to ten attempts in ten minutes for a single user account and 50 attempts in one hour for a single IP address.

If a user administrator changes another user's password, the user's one-time password credentials will be erased since they will no longer be accessible with the user's new password. A warning is displayed on the user profile page to alert user administrators about this.

Users are notified by email when their one-time password credentials are added, updated, or removed, when backup codes for their accounts are created or regenerated, and when backup codes are used.

Users' passwords are required in order to update or clear credentials with the exception that user administrators are allowed to clear others' credentials.
