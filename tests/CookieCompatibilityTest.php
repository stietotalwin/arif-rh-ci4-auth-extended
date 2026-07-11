<?php

declare(strict_types=1);

namespace StieTotalWin\AuthTests;

use PHPUnit\Framework\TestCase;
use StieTotalWin\Auth\Auth;
use StieTotalWin\Auth\CookieSpy;

final class CookieCompatibilityTest extends TestCase
{
	protected function setUp(): void
	{
		CookieSpy::reset();
		unset($_COOKIE['auth_session'], $_COOKIE['tw_auth_session']);
	}

	protected function tearDown(): void
	{
		CookieSpy::reset();
		unset($_COOKIE['auth_session'], $_COOKIE['tw_auth_session']);
	}

	public function testSetCookieUsesCodeIgniterCookieConfiguration(): void
	{
		$auth = $this->newAuthWithoutConstructor();

		$setCookie = new \ReflectionMethod($auth, 'setCookie');
		$setCookie->invoke($auth, 'hash', 1_800_000_000);

		self::assertSame(
			['tw_auth_session', 'hash', 1_800_000_000, '/pmb', '.example.test', true, true],
			CookieSpy::$calls[0],
		);
		self::assertSame('hash', $_COOKIE['tw_auth_session']);
	}

	public function testDeletingCookieExpiresAndRemovesPrefixedCookie(): void
	{
		$auth = $this->newAuthWithoutConstructor();
		$_COOKIE['tw_auth_session'] = 'hash';
		$expectedExpiry = time() - 3600;

		$setCookie = new \ReflectionMethod($auth, 'setCookie');
		$setCookie->invoke($auth);

		self::assertCount(1, CookieSpy::$calls);
		self::assertSame('tw_auth_session', CookieSpy::$calls[0][0]);
		self::assertSame('', CookieSpy::$calls[0][1]);
		self::assertEqualsWithDelta($expectedExpiry, CookieSpy::$calls[0][2], 2);
		self::assertSame(
			['/pmb', '.example.test', true, true],
			array_slice(CookieSpy::$calls[0], 3),
		);
		self::assertArrayNotHasKey('tw_auth_session', $_COOKIE);
	}

	public function testCurrentSessionHashUsesPrefixedCookieName(): void
	{
		$auth = $this->newAuthWithoutConstructor();
		$_COOKIE['auth_session'] = 'unprefixed-hash';
		$_COOKIE['tw_auth_session'] = 'prefixed-hash';

		self::assertSame('prefixed-hash', $auth->getCurrentSessionHash());

		unset($_COOKIE['tw_auth_session']);

		self::assertSame('', $auth->getCurrentSessionHash());
	}

	public function testDatabaseBackedConfigPropertiesDoNotEmitDeprecations(): void
	{
		$deprecations = [];
		set_error_handler(static function (int $severity, string $message) use (&$deprecations): bool {
			if ($severity === E_DEPRECATED) {
				$deprecations[] = $message;

				return true;
			}

			return false;
		});

		$config = new \StieTotalWin\Auth\Config\Auth();
		$config->siteTimezone = 'Asia/Jakarta';
		restore_error_handler();

		self::assertSame([], $deprecations);
	}

	private function newAuthWithoutConstructor(): Auth
	{
		$auth = (new \ReflectionClass(Auth::class))->newInstanceWithoutConstructor();
		$auth->config = (object) ['cookieName' => 'auth_session'];
		$auth->cookieConfig = (object) [
			'prefix'   => 'tw_',
			'path'     => '/pmb',
			'domain'   => '.example.test',
			'secure'   => true,
			'httponly' => true,
		];

		return $auth;
	}
}
