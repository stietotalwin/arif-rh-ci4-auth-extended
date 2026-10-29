<?php

declare(strict_types=1);

namespace StieTotalWin\AuthTests;

use StieTotalWin\Auth\Auth;
use StieTotalWin\DynaModel\DB;
use PHPUnit\Framework\TestCase;

/**
 * Proves password login keeps its current results and that loginByUid opens
 * an equivalent session for a uid the caller has already verified.
 */
final class LoginByUidTest extends TestCase
{
	private const string PASSWORD = 'admin@PRO#123';

	private Auth $auth;

	/** @var list<int> */
	private array $userIds = [];

	private mixed $concurrentSessions = null;

	public function setUp(): void
	{
		$config = new \StieTotalWin\Auth\Config\Auth();
		$config->enableLoginID = true;

		$this->auth = new Auth($config);
		$this->auth->testMode();
		$this->auth->config->sendMailCallback = static fn (array $message): bool => true;
		$this->concurrentSessions = $this->auth->config->allowConcurrentSessions;

		unset($_COOKIE[$this->cookieName()]);
		$this->auth->isAuthenticated = false;

		DB::table($this->auth->config->authAttemptTable)->truncate();
	}

	public function tearDown(): void
	{
		$this->auth->config->allowConcurrentSessions = $this->concurrentSessions;
		unset($_COOKIE[$this->cookieName()]);

		foreach ($this->userIds as $uid) {
			$this->auth->deleteAccount($uid);
		}

		DB::table($this->auth->config->authAttemptTable)->truncate();
		$this->userIds = [];
	}

	public function testPasswordLoginKeepsExistingFailureMessagesAndSession(): void
	{
		$activeEmail   = 'active-messages@login-by-uid.test';
		$inactiveEmail = 'inactive-messages@login-by-uid.test';
		$activeId      = $this->registerAccount($activeEmail, 'active-messages', true);
		$this->registerAccount($inactiveEmail, 'inactive-messages', false);

		$invalid = $this->auth->login('invalid-email.com', self::PASSWORD);
		$this->assertFailure($invalid, lang('Auth.email_invalid'));

		$weak = $this->auth->login($activeEmail, '123456');
		$this->assertFailure($weak, lang('Auth.password_weak'));

		$missing = $this->auth->login('missing@login-by-uid.test', self::PASSWORD);
		$this->assertFailure($missing, lang('Auth.account_not_found'));

		$wrong = $this->auth->login($activeEmail, self::PASSWORD . '-wrong');
		$this->assertFailure($wrong, lang('Auth.email_password_incorrect'));

		$inactive = $this->auth->login($inactiveEmail, self::PASSWORD);
		$this->assertFailure($inactive, lang('Auth.account_inactive'));
		$this->assertSame([], $this->sessionsForUid($this->uidFor($inactiveEmail)));
		$this->assertContains(
			'Login::' . lang('Auth.account_inactive'),
			array_column($this->attemptRows(), 'note'),
		);

		// checkSession() still counts every attempt on the IP. Clear the
		// failures above so the session check is not tripped by that total.
		DB::table($this->auth->config->authAttemptTable)->truncate();

		$opened = $this->auth->login($activeEmail, self::PASSWORD);
		$this->assertSuccess($opened);
		$this->assertTrue($this->auth->checkSession($opened['hash']));
		$this->assertSame($activeId, $this->auth->getCurrentUID());

		$laterFailure = $this->auth->login($inactiveEmail, self::PASSWORD);
		$this->assertFailure($laterFailure, lang('Auth.account_inactive'));
		$this->assertSame($opened['hash'], $this->auth->getCurrentSessionHash());
		$this->assertTrue($this->auth->checkSession($opened['hash']));
	}

	public function testLoginByLoginIDKeepsPasswordLoginResults(): void
	{
		$activeEmail   = 'active-login-id@login-by-uid.test';
		$inactiveEmail = 'inactive-login-id@login-by-uid.test';
		$activeId      = $this->registerAccount($activeEmail, 'active-login-id', true);
		$this->registerAccount($inactiveEmail, 'inactive-login-id', false);

		$unknown = $this->auth->loginByLoginID('nobody-login-id', self::PASSWORD);
		$this->assertFailure($unknown, lang('Auth.account_not_found'));

		$wrong = $this->auth->loginByLoginID('active-login-id', self::PASSWORD . '-wrong');
		$this->assertFailure($wrong, lang('Auth.email_password_incorrect'));

		$inactive = $this->auth->loginByLoginID('inactive-login-id', self::PASSWORD);
		$this->assertFailure($inactive, lang('Auth.account_inactive'));

		$opened = $this->auth->loginByLoginID('active-login-id', self::PASSWORD, true);
		$this->assertSuccess($opened);
		$this->assertSame($activeId, (int) $this->sessionByHash($opened['hash'])['uid']);
		$this->assertExpiresWithRemember($opened['hash'], true);
	}

	public function testLoginByUidMatchesPasswordSession(): void
	{
		$email = 'active-session@login-by-uid.test';
		$uid   = $this->registerAccount($email, 'active-session', true);
		$agent = 'SIAKAD-PasskeyTest/2.2';
		$hadAgent = array_key_exists('HTTP_USER_AGENT', $_SERVER);
		$previousAgent = $_SERVER['HTTP_USER_AGENT'] ?? null;
		$_SERVER['HTTP_USER_AGENT'] = $agent;

		try {
			foreach ([false, true] as $remember) {
				$attemptsBefore = count($this->attemptRows());
				$password = $this->auth->login($email, self::PASSWORD, $remember);
				$this->assertSuccess($password);
				$this->assertSame($attemptsBefore, count($this->attemptRows()));
				$passwordSession = $this->sessionByHash($password['hash']);

				$this->auth->logout($password['hash']);

				$byUid = $this->auth->loginByUid($uid, $remember);
				$this->assertSuccess($byUid);
				$this->assertSame($attemptsBefore, count($this->attemptRows()));
				$uidSession = $this->sessionByHash($byUid['hash']);

				$this->assertSame(array_keys($passwordSession), array_keys($uidSession));
				$this->assertSame((int) $passwordSession['uid'], (int) $uidSession['uid']);
				$this->assertSame($passwordSession['ip'], $uidSession['ip']);
				$this->assertSame($agent, $uidSession['agent']);
				$this->assertSame($passwordSession['agent'], $uidSession['agent']);
				$this->assertNotSame($password['hash'], $byUid['hash']);
				$this->assertMatchesRegularExpression('/^[0-9a-f]{40}$/', $byUid['hash']);
				$this->assertSame(sha1($byUid['hash'] . $this->auth->config->siteKey), $uidSession['cookie_crc']);
				$this->assertExpiresWithRemember($byUid['hash'], $remember);
				$this->assertSame($byUid['hash'], $this->auth->getCurrentSessionHash());
				$this->assertTrue($this->auth->checkSession($byUid['hash']));
				$this->assertTrue($this->auth->isLogged());
				$this->assertSame($uid, $this->auth->getCurrentUID());
				$this->assertSame($email, $this->auth->getCurrentUser()['email']);

				$this->auth->logout($byUid['hash']);
			}
		} finally {
			if ($hadAgent) {
				$_SERVER['HTTP_USER_AGENT'] = $previousAgent;
			} else {
				unset($_SERVER['HTTP_USER_AGENT']);
			}
		}
	}

	public function testLoginByUidHonorsConcurrentSessionSetting(): void
	{
		$email = 'active-concurrent@login-by-uid.test';
		$uid   = $this->registerAccount($email, 'active-concurrent', true);

		$this->auth->config->allowConcurrentSessions = false;
		$first = $this->auth->loginByUid($uid);
		$this->assertSuccess($first);

		$second = $this->auth->loginByUid($uid, true);
		$this->assertSuccess($second);
		$this->assertNull($this->findSession($first['hash']));
		$this->assertIsArray($this->findSession($second['hash']));
		$this->assertSame($second['hash'], $this->auth->getCurrentSessionHash());
		$this->assertFalse($this->auth->checkSession($first['hash']));
		$this->assertTrue($this->auth->checkSession($second['hash']));
		$this->assertCount(1, $this->sessionsForUid($uid));
		$this->assertExpiresWithRemember($second['hash'], true);

		$this->auth->logout($second['hash']);
		$this->auth->config->allowConcurrentSessions = true;

		$password = $this->auth->login($email, self::PASSWORD);
		$this->assertSuccess($password);

		$byUid = $this->auth->loginByUid($uid);
		$this->assertSuccess($byUid);
		$this->assertIsArray($this->findSession($password['hash']));
		$this->assertIsArray($this->findSession($byUid['hash']));
		$this->assertCount(2, $this->sessionsForUid($uid));
		$this->assertTrue($this->auth->checkSession($password['hash']));
		$this->assertTrue($this->auth->checkSession($byUid['hash']));
		$this->assertSame($byUid['hash'], $this->auth->getCurrentSessionHash());
	}

	public function testLoginByUidFailureDoesNotRevealWhetherTheAccountExists(): void
	{
		$inactiveEmail = 'inactive-hidden@login-by-uid.test';
		$inactiveId    = $this->registerAccount($inactiveEmail, 'inactive-hidden', false);
		$unknownId     = 910001;

		$unknown  = $this->auth->loginByUid($unknownId);
		$inactive = $this->auth->loginByUid($inactiveId);
		$zero     = $this->auth->loginByUid(0);
		$negative = $this->auth->loginByUid(-1);

		$this->assertFailure($unknown, lang('Auth.login_failed'));
		$this->assertSame($unknown['message'], $inactive['message']);
		$this->assertSame($unknown['message'], $zero['message']);
		$this->assertSame($unknown['message'], $negative['message']);
		$this->assertNotSame(lang('Auth.account_not_found'), $unknown['message']);
		$this->assertNotSame(lang('Auth.account_inactive'), $unknown['message']);
		$this->assertSame([], $this->sessionsForUid($inactiveId));
		$this->assertSame([], $this->sessionsForUid($unknownId));

		$inactiveAttempts = $this->attemptsFor(strtolower($inactiveEmail));
		$this->assertCount(1, $inactiveAttempts);
		$this->assertSame('Login::' . $inactive['message'], $inactiveAttempts[0]['note']);
		$this->assertCount(1, $this->attemptsFor('uid:' . $unknownId));
		$this->assertSame([], $this->attemptsFor(''));
	}

	public function testLoginByUidFailureLeavesExistingSessionAlone(): void
	{
		$email = 'active-untouched@login-by-uid.test';
		$uid   = $this->registerAccount($email, 'active-untouched', true);
		$opened = $this->auth->loginByUid($uid);

		$this->assertSuccess($opened);

		$failed = $this->auth->loginByUid(910002);
		$this->assertFailure($failed, lang('Auth.login_failed'));
		$this->assertSame($opened['hash'], $this->auth->getCurrentSessionHash());
		$this->assertIsArray($this->findSession($opened['hash']));
		$this->assertTrue($this->auth->checkSession($opened['hash']));
	}

	public function testLoginByUidLockoutIsSharedWithPasswordLogin(): void
	{
		$email = 'active-shared-lock@login-by-uid.test';
		$uid   = $this->registerAccount($email, 'active-shared-lock', true);
		$limit = (int) $this->auth->config->attemptsBeforeLocked;

		for ($i = 0; $i < $limit; $i++) {
			$failed = $this->auth->login($email, self::PASSWORD . '-wrong');
			$this->assertFailure($failed, lang('Auth.email_password_incorrect'));
		}

		$blocked = $this->auth->loginByUid($uid);
		$this->assertFailure($blocked, lang('Auth.user_blocked'));
		$this->assertSame([], $this->sessionsForUid($uid));
		$this->assertCount($limit, $this->attemptsFor(strtolower($email)));

		DB::table($this->auth->config->authAttemptTable)->truncate();

		$inactiveEmail = 'inactive-shared-lock@login-by-uid.test';
		$inactiveId    = $this->registerAccount($inactiveEmail, 'inactive-shared-lock', false);

		for ($i = 0; $i < $limit; $i++) {
			$failed = $this->auth->loginByUid($inactiveId);
			$this->assertFailure($failed, lang('Auth.login_failed'));
		}

		$byPassword = $this->auth->login($inactiveEmail, self::PASSWORD);
		$this->assertFailure($byPassword, lang('Auth.user_blocked'));
		$this->assertCount($limit, $this->attemptsFor(strtolower($inactiveEmail)));
		$this->assertSame([], $this->attemptsFor('uid:' . $inactiveId));
	}

	public function testLoginByUidLockoutStaysScopedToTheAccount(): void
	{
		$blockedEmail = 'inactive-scoped@login-by-uid.test';
		$openEmail    = 'active-scoped@login-by-uid.test';
		$blockedId    = $this->registerAccount($blockedEmail, 'inactive-scoped', false);
		$openId       = $this->registerAccount($openEmail, 'active-scoped', true);
		$limit        = (int) $this->auth->config->attemptsBeforeLocked;

		for ($i = 0; $i < $limit; $i++) {
			$this->assertFailure($this->auth->loginByUid($blockedId), lang('Auth.login_failed'));
		}

		$this->assertFailure($this->auth->loginByUid($blockedId), lang('Auth.user_blocked'));

		$other = $this->auth->loginByUid($openId);
		$this->assertSuccess($other);
		$this->assertSame($openId, (int) $this->sessionByHash($other['hash'])['uid']);

		$this->auth->logout($other['hash']);

		for ($i = 0; $i < $limit; $i++) {
			$this->assertFailure($this->auth->loginByUid(920001), lang('Auth.login_failed'));
		}

		$this->assertFailure($this->auth->loginByUid(920001), lang('Auth.user_blocked'));
		$this->assertFailure($this->auth->loginByUid(920002), lang('Auth.login_failed'));

		$again = $this->auth->login($openEmail, self::PASSWORD);
		$this->assertSuccess($again);
	}

	public function testOverriddenAddSessionIsUsedByPasswordAndUidLogin(): void
	{
		$auth = new SessionRecordingAuth(new \StieTotalWin\Auth\Config\Auth());
		$auth->testMode();
		$auth->config->sendMailCallback = static fn (array $message): bool => true;
		$this->auth = $auth;

		$email = 'active-override@login-by-uid.test';
		$uid   = $this->registerAccount($email, 'active-override', true);

		$wrong = $auth->login($email, self::PASSWORD . '-wrong');
		$this->assertFailure($wrong, lang('Auth.email_password_incorrect'));
		$this->assertSame(0, $auth->addSessionCalls);

		$password = $auth->login($email, self::PASSWORD);
		$this->assertSuccess($password);
		$this->assertSame(1, $auth->addSessionCalls);

		$auth->logout($password['hash']);
		$missing = $auth->loginByUid(930001);
		$this->assertFailure($missing, lang('Auth.login_failed'));
		$this->assertSame(1, $auth->addSessionCalls);

		$byUid = $auth->loginByUid($uid);
		$this->assertSuccess($byUid);
		$this->assertSame(2, $auth->addSessionCalls);
		$this->assertSame($byUid['hash'], $auth->getCurrentSessionHash());
	}

	private function registerAccount(string $email, string $username, bool $active): int
	{
		$result = $this->auth->register($email, self::PASSWORD, self::PASSWORD, [
			'fullname' => 'Passkey User',
			'username' => $username,
			'group_id' => 1,
			'role_id'  => 1,
		], ! $active);

		$this->assertFalse($result['error'], $result['message'] ?? '');

		$uid = $this->auth->getUID(strtolower($email));
		$this->assertIsInt($uid);
		$this->userIds[] = $uid;

		return $uid;
	}

	private function uidFor(string $email): int
	{
		$uid = $this->auth->getUID(strtolower($email));
		$this->assertIsInt($uid);

		return $uid;
	}

	/**
	 * @param array<string, mixed> $result
	 */
	private function assertSuccess(array $result): void
	{
		$this->assertSame(['error', 'message', 'hash', 'cookieName'], array_keys($result));
		$this->assertFalse($result['error']);
		$this->assertSame(lang('Auth.logged_in'), $result['message']);
		$this->assertSame($this->auth->config->cookieName, $result['cookieName']);
		$this->assertSame($result['hash'], $this->auth->getCurrentSessionHash());
	}

	/**
	 * @param array<string, mixed> $result
	 */
	private function assertFailure(array $result, string $message): void
	{
		$this->assertSame(['error', 'message'], array_keys($result));
		$this->assertTrue($result['error']);
		$this->assertSame($message, $result['message']);
	}

	private function assertExpiresWithRemember(string $hash, bool $remember): void
	{
		$lifetime = $remember ? $this->auth->config->cookieRemember : $this->auth->config->cookieForget;

		$this->assertEqualsWithDelta(
			strtotime((string) $lifetime),
			strtotime((string) $this->sessionByHash($hash)['expire_date']),
			2,
		);
	}

	/**
	 * @return array<string, mixed>
	 */
	private function sessionByHash(string $hash): array
	{
		$session = $this->findSession($hash);
		$this->assertIsArray($session);

		return $session;
	}

	/**
	 * @return array<string, mixed>|null
	 */
	private function findSession(string $hash): ?array
	{
		$row = DB::table($this->auth->config->authSessionTable)->asArray()->findOneBy(['hash' => $hash]);

		return is_array($row) ? $row : null;
	}

	/**
	 * @return list<array<string, mixed>>
	 */
	private function sessionsForUid(int $uid): array
	{
		$rows = DB::table($this->auth->config->authSessionTable)->asArray()->findBy(['uid' => $uid]);

		return is_array($rows) ? array_values($rows) : [];
	}

	/**
	 * @return list<array<string, mixed>>
	 */
	private function attemptRows(): array
	{
		$rows = DB::table($this->auth->config->authAttemptTable)->asArray()->findAll();

		return is_array($rows) ? array_values($rows) : [];
	}

	/**
	 * @return list<array<string, mixed>>
	 */
	private function attemptsFor(string $identifier): array
	{
		return array_values(array_filter(
			$this->attemptRows(),
			static fn (array $row): bool => ($row['identifier'] ?? null) === $identifier,
		));
	}

	private function cookieName(): string
	{
		return $this->auth->cookieConfig->prefix . $this->auth->config->cookieName;
	}
}

/**
 * Records session creation so subclasses that override addSession keep working.
 */
class SessionRecordingAuth extends Auth
{
	public int $addSessionCalls = 0;

	protected function addSession(int $uid, bool $remember = false)
	{
		$this->addSessionCalls++;

		return parent::addSession($uid, $remember);
	}
}
