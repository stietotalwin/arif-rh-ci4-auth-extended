# Changelog

## 2.2.0

### Added

- `Auth::loginByUid(int $uid, bool $remember = false)` opens an `auth_sessions` row and auth cookie for a uid the caller has already verified (for example after WebAuthn).
- Unknown and inactive accounts return the same `Auth.login_failed` message.
- When the uid exists, lockout and attempt records use that account's email, so they share the password-login bucket. A missing uid uses its own `uid:{id}` bucket.

### Changed

- `login()` and `loginByLoginID()` finish through the same session path as `loginByUid`.
- Return values stay `error`, `message`, and on success `hash` and `cookieName`.

Passkey credential storage stays in the application. This release does not add a `user_passkeys` table.
