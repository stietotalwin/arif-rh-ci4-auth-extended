<?php

namespace StieTotalWin\Auth;

final class CookieSpy
{
	public static array $calls = [];

	public static function reset(): void
	{
		self::$calls = [];
	}
}

function setcookie(
	string $name,
	string $value = '',
	array|int $expires_or_options = 0,
	?string $path = null,
	?string $domain = null,
	?bool $secure = null,
	?bool $httponly = null,
): bool {
	CookieSpy::$calls[] = func_get_args();

	return true;
}
