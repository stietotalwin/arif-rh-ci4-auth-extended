# PHPAuth for CodeIgniter 4

This package is adopted from [PHPAuth](https://github.com/PHPAuth/PHPAuth), but completedly rewrited for easy implementation with CodeIgniter 4.

## Installation

1. `composer require stietotalwin/arif-rh-ci4-auth-extended`
2. make sure you have set you database config properly
3. `php spark migrate -n StieTotalWin\Auth`
4. `php spark db:seed \\StieTotalWin\\Auth\\Database\\Seeds\\AuthSeeder`

## Features

- Register
- Activation email
- Login
- Login for an already verified user id (`loginByUid`, for example after WebAuthn)
- Request reset password
- Encrypt password using bcrypt
- Prevent brute force attack by limiting request

## Login by verified uid (2.2.0)

`Auth::loginByUid(int $uid, bool $remember = false)` opens the same session as a successful password login: `auth_sessions`, the auth cookie, remember-me, `allow_concurrent_sessions`, the active-account check, and the same lockout and attempt records.

Call it only after the application has already verified that uid. A passkey (WebAuthn) check belongs in the app. This method does not check a password or a passkey. Do not pass an id taken straight from the request.

Unknown and inactive accounts both return `Auth.login_failed`, so that message does not reveal whether the uid exists. An existing account shares the password-login lockout bucket (its email), so `Auth.user_blocked` can still tell a locked existing uid apart from an unknown one. `login()` and `loginByLoginID()` use this same session path; their `error` / `message` / `hash` / `cookieName` results are unchanged.

Passkey credential storage is not part of this package. Relying-party settings differ per app, and a credential table without the WebAuthn ceremony would be incomplete.

## Acknowledgments

- [PHPAuth](https://github.com/PHPAuth/PHPAuth)
