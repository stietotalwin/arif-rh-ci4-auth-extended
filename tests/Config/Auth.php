<?php

namespace StieTotalWin\AuthTests\Config;

/**
 * PHPAuth Config class
 */

class Auth extends \StieTotalWin\Auth\Config\Auth
{
	/**
	 * Cost used in Bcript
	 *
	 * @var int $bcryptCost
	 */
	public $bcryptCost = 12;

	public $enableLoginID = true;
}