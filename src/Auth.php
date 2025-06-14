<?php
namespace StieTotalWin\Auth;

/**
 * PHPAuth for CodeIgniter 4
 *
 */

use StieTotalWin\DynaModel\DB;
use CodeIgniter\Config\BaseConfig;
use ZxcvbnPhp\Zxcvbn;

/**
 * Auth class
 *
 */
class Auth
{
	public const HASH_LENGTH  = 40;
	public const TOKEN_LENGTH = 20;

	/**
	 * Auth Configuration
	 *
	 * @var \stdClass
	 */
	public $config;

	/**
	 * Cookie Configuration
	 *
	 * @var \stdClass
	 */
	public $cookieConfig;

	/**
	 * Public 'is_logged' field
	 *
	 * @var bool
	 */
	public $isAuthenticated = false;

	/**
	 * testMode
	 *
	 * @var bool
	 */
	public $testMode = false;

	/**
	 * Current user login
	 *
	 * @var array|null
	 */
	protected $currentUser = null;

	/**
	 * User Roles
	 *
	 * @var array
	 */
	protected $roles = [];

	/**
	 * User Groups
	 *
	 * @var array
	 */
	protected $groups = [];

	/**
	 * Initiates database connection
	 *
	 * @param BaseConfig|null $config
	 *
	 * @return void
	 */
	public function __construct(BaseConfig $config = null)
	{
		$this->getConfig($config);

		$this->roles  = $this->getRoles();
		$this->groups = $this->getGroups();

		date_default_timezone_set($this->config->siteTimezone);

		helper('cookie');

		$this->isAuthenticated = $this->isLogged();
	}

	/**
	 * Get All Auth Configuration
	 *
	 * @param BaseConfig|null $config
	 *
	 * @return void
	 */
	public function getConfig(BaseConfig $config = null)
	{
		if ($config instanceof BaseConfig) {
			$this->config = $config;
		} else {
			$this->config = \CodeIgniter\Config\Factories::config('Auth');
		}

		$this->cookieConfig = config(\Config\App::class);

		$tblConfig  = DB::table($this->config->configTable);
		$configVals = $tblConfig->asObject()->findAll();

		foreach ($configVals as $config) {
			$this->config->{camelize($config->name)} = $config->value;
		}
	}

	/**
	 * Logs a user in
	 *
	 * @param string $email
	 * @param string $password
	 * @param bool   $remember
	 *
	 * @return array{error: bool, message: string, hash?: string, cookieName?: string}
	 */
	public function login(string $email, string $password, bool $remember = false)
	{
		$return['error'] = true;

		if ($this->isIPLocked()) {
			$return['message'] = lang("Auth.user_blocked");
			return $return;
		}

		$validateEmail = $this->validateEmail($email);

		if ($validateEmail['error']) {
			$return['message'] = $validateEmail['message'];

			$this->addAttempt('Login::' . $return['message']);

			return $return;
		}

		$validatePassword = $this->validatePassword($password);
		if ($validatePassword['error']) {
			$return['message'] = $validatePassword['message'];

			$this->addAttempt('Login::' . $return['message']);

			return $return;
		}

		$uid = $this->getUID(strtolower($email));

		if (!$uid) {
			$return['message'] = lang("Auth.account_not_found");

			$this->addAttempt('Login::' . $return['message']);

			return $return;
		}

		$user = $this->getUser($uid, true);

		if (!$this->passwordVerifyWithRehash($password, $user['password'], $uid)) {
			$return['message'] = lang("Auth.email_password_incorrect");

			$this->addAttempt('Login::' . $return['message']);

			return $return;
		}

		if ((int) $user['active'] !== 1) {
			$return['message'] = lang("Auth.account_inactive");

			$this->addAttempt('Login::' . $return['message']);

			return $return;
		}

		$sessiondata = $this->addSession($user['uid'], $remember);

		if ($sessiondata === false) {
			$return['message'] = lang('Auth.system_error');

			return $return;
		}

		$return['error']   = false;
		$return['message'] = lang("Auth.logged_in");

		$return['hash'] = $sessiondata['hash'];

		$return['cookieName'] = $this->config->cookieName;

		return $return;
	}

	/**
	 * Logs a user in by LoginID
	 *
	 * @param string $loginID
	 * @param string $password
	 * @param bool   $remember
	 *
	 * @return array{error: bool, message: string, hash?: string, cookieName?: string}
	 */
	public function loginByLoginID(string $loginID, string $password, bool $remember = false)
	{
		$return['error'] = true;

		if ($this->config->enableLoginID) {
			$user = $this->getUserByLoginID($loginID);

			if (isset($user['email'])) {
				$email = $user['email'];

				return $this->login($email, $password, $remember);
			}
		}

		$return['message'] = lang("Auth.account_not_found");

		$this->addAttempt('Login::' . $return['message']);

		return $return;
	}

	/**
	 * Creates a new user, adds them to database
	 *
	 * @param string $email
	 * @param string $password
	 * @param string $repeatPassword
	 * @param array  $params
	 * @param bool   $useEmailActivation
	 *
	 * @return array{error: bool, message: string}
	 */
	public function register(string $email, string $password, string $repeatPassword, array $params = [], bool $useEmailActivation = true)
	{
		$return['error'] = true;

		if ($this->isIPLocked()) {
			$return['message'] = lang('Auth.user_blocked');
		} elseif ($password !== $repeatPassword) {
			$return['message'] = lang('Auth.password_nomatch');
		} else {
			$addUser = $this->addUser($email, $password, $params, $useEmailActivation);

			if ($addUser['error']) {
				$return['message'] = $addUser['message'];
			} else {
				$return['error']   = false;
				$return['message'] =
					($useEmailActivation ? lang('Auth.register_success')
						: lang('Auth.register_success_emailmessage_suppressed'));
			}
		}

		return $return;
	}

	/**
	 * Activates a user's account
	 *
	 * @param string $activationToken
	 * @return array{error: bool, message: string}
	 */
	public function activateUserAccount(string $activationToken)
	{
		$return['error'] = true;

		if ($this->isIPLocked()) {
			$return['message'] = lang("Auth.user_blocked");
		} elseif (strlen($activationToken) !== self::TOKEN_LENGTH) {
			$return['message'] = lang("Auth.activationkey_invalid");

			$this->addAttempt('activateUserAccount::' . $return['message']);
		} else {
			$request = $this->getRequest($activationToken, "activation");

			if ($request['error']) {
				$return['message'] = $request['message'];
			} else {
				$userTable = DB::table($this->config->userTable);

				$updated = $userTable->update($request['uid'], ['active' => 1]);

				if ($updated) {
					$this->deleteRequest($request['id']);
				}

				$return['error']   = false;
				$return['message'] = lang("Auth.account_activated");
			}
		}

		return $return;
	}

	/**
	 * Creates a reset key for an email address and sends email
	 * @param string $email
	 *
	 * @return array{error: bool, message: string}
	 */
	public function requestReset(string $email)
	{
		$state['error'] = true;

		if ($this->isIPLocked()) {
			// @codeCoverageIgnoreStart
			$state['message'] = lang("Auth.user_blocked");
			// @codeCoverageIgnoreEnd
		} elseif (!$this->isEmailTaken($email)) {
			$state['message'] = lang("Auth.email_incorrect");

			$this->addAttempt('requestReset::' . $state['message']);
		} else {
			$uid = $this->getUID($email);

			$addRequest = $this->addRequest($uid, $email, 'reset');

			if ($addRequest['error']) {
				// @codeCoverageIgnoreStart
				$state['message'] = $addRequest['message'];

				$this->addAttempt('requestReset::' . $state['message']);
				// @codeCoverageIgnoreEnd
			} else {
				$state['error']   = false;
				$state['message'] = lang('Auth.reset_requested');
			}
		}

		return $state;
	}

	/**
	 * Logs out the session, identified by hash
	 *
	 * @param string $hash
	 *
	 * @return void
	 */
	public function logout(string $hash)
	{
		if (strlen($hash) === self::HASH_LENGTH) {
			$this->isAuthenticated = false;
			$this->currentUser     = null;

			$this->deleteSession($hash);
		}
	}

	/**
	 * Logs out of all sessions for specified uid
	 *
	 * @param int $uid
	 *
	 * @return bool
	 */
	public function logoutAll(int $uid)
	{
		$this->isAuthenticated = false;
		$this->currentUser     = null;

		return $this->deleteExistingSessions($uid);
	}

	/**
	 * Hashes provided password with Bcrypt
	 *
	 * @param string $password
	 *
	 * @return string
	 */
	public function getHash(string $password)
	{
		return password_hash($password, PASSWORD_BCRYPT, ['cost' => $this->config->bcryptCost]);
	}

	/**
	 * Creates a session for a specified user id
	 *
	 * @param int  $uid
	 * @param bool $remember
	 *
	 * @return array|false
	 */
	protected function addSession(int $uid, bool $remember = false)
	{
		$ip = $this->getIp();

		$user = $this->getUser($uid);

		if ($user) {
			$data['hash'] = sha1($this->config->siteKey . microtime());

			$agent = $_SERVER['HTTP_USER_AGENT'] ?? '';

			if (!$this->config->allowConcurrentSessions) {
				$this->deleteExistingSessions($uid);
			}

			if ($remember) {
				$data['expire'] = strtotime($this->config->cookieRemember);
			} else {
				$data['expire'] = strtotime($this->config->cookieForget);
			}

			$data['cookie_crc'] = sha1($data['hash'] . $this->config->siteKey);

			$sessTable = DB::table($this->config->authSessionTable);

			$saved = $sessTable->insert([
				'uid'         => $uid,
				'hash'        => $data['hash'],
				'expire_date' => date('Y-m-d H:i:s', $data['expire']),
				'ip'          => $ip,
				'agent'       => $agent,
				'cookie_crc'  => $data['cookie_crc'],
			]);

			$this->setCookie($data['hash'], $data['expire']);

			return $data;
		}

		return false;
	}

	/**
	 * Set Test mode
	 *
	 * @param bool $testMode
	 *
	 * @return $this
	 */
	public function testMode(bool $testMode = true)
	{
		$this->testMode = $testMode;
		return $this;
	}

	/**
	 * Set Cookie
	 *
	 * @param string     $value
	 * @param int|false  $expire if set as false, it will delete the cookie
	 *
	 * @return void
	 */
	protected function setCookie(string $value = '', $expire = false)
	{
		$appConfig = $this->cookieConfig;

		$deleteCookie = (is_bool($expire) && !$expire && empty($value));

		if ($deleteCookie) {
			$expire = time() - 3600;

			// make sure that getCurrentSessionHash will not get the cookie
			unset($_COOKIE[$appConfig->cookiePrefix . $this->config->cookieName]);
		}

		if (!$this->testMode) {
			setcookie(
				$appConfig->cookiePrefix . $this->config->cookieName,
				$value,
				$expire,
				$appConfig->cookiePath,
				$appConfig->cookieDomain,
				$appConfig->cookieSecure,
				$appConfig->cookieHTTPOnly,
			);
		}

		if (!$deleteCookie) {
			// make it available immediately for getCurrentSessionHash
			$_COOKIE[$appConfig->cookiePrefix . $this->config->cookieName] = $value;
		}
	}

	/**
	 * Removes all existing sessions for a given UID
	 * @param int $uid
	 *
	 * @return bool
	 */
	protected function deleteExistingSessions(int $uid)
	{
		$sessTable = DB::table($this->config->authSessionTable);

		$sessTable->deleteBy(['uid' => $uid]);

		$this->setCookie();
		
		return true;
	}

	/**
	 * Removes a session based on hash
	 *
	 * @param string $hash
	 *
	 * @return void
	 */
	protected function deleteSession(string $hash)
	{
		$sessTable = DB::table($this->config->authSessionTable);

		$sessTable->deleteBy(['hash' => $hash]);

		$this->setCookie();
	}

	/**
	 * Function to check if a session is valid
	 *
	 * @param string $hash
	 *
	 * @return bool
	 */
	public function checkSession(string $hash)
	{

		$ip = $this->getIp();

		if ($this->isIPLocked()) {
			$return['message'] = lang("Auth.user_blocked");
			return false;
		}

		if (strlen($hash) != self::HASH_LENGTH) {
			return false;
		}

		$sessionTable = DB::table($this->config->authSessionTable);

		$row = $sessionTable
			->select('id, uid, expire_date, ip, agent, cookie_crc')
			->asArray()
			->findOneBy(['hash' => $hash]);

		if (!is_array($row)) {
			return false;
		}

		$uid         = $row['uid'];
		$expireDate  = strtotime($row['expire_date']);
		$currentdate = strtotime(date("Y-m-d H:i:s"));
		$dbIP        = $row['ip'];
		$dbCookie    = $row['cookie_crc'];

		if ($currentdate > $expireDate) {
			$this->deleteSession($hash);
			return false;
		}

		if ($ip !== $dbIP) {
			return false;
		}

		if ($dbCookie === sha1($hash . $this->config->siteKey)) {
			if ($expireDate - $currentdate < strtotime($this->config->cookieRenew) - $currentdate) {
				$this->deleteSession($hash);
				$this->addSession($uid, false);
			}
			return true;
		}

		return false;
	}

	/**
	 * Checks if an email is already in use
	 *
	 * @param string $email
	 *
	 * @return bool
	 */
	public function isEmailTaken(string $email)
	{
		$userTable = DB::table($this->config->userTable);

		$user = $userTable->asObject()->findOneBy(['email' => $email]);

		return is_object($user);
	}

	/**
	 * Adds a new user to database
	 * @param string $email      -- email
	 * @param string $password   -- password
	 * @param array  $params      -- additional params
	 * @param bool   $useEmailActivation  -- activate email confirm or not
	 *
	 * @return array{error: bool, message?: string}
	 */
	protected function addUser(string $email, string $password, array $params = [], bool $useEmailActivation = true)
	{
		$return['error'] = true;

		$validateEmail = $this->validateEmail($email);

		if ($validateEmail['error']) {
			$return['message'] = $validateEmail['message'];
			return $return;
		}

		$validatePassword = $this->validatePassword($password);

		if ($validatePassword['error']) {
			$return['message'] = $validatePassword['message'];
			return $return;
		}

		if ($this->isEmailTaken($email)) {
			$return['message'] = lang("Auth.email_taken", [$email]);

			$this->addAttempt('addUser::' . $return['message']);

			return $return;
		}

		$userTable = DB::table($this->config->userTable);

		$userData = array_merge([
			'email'    => $email,
			'password' => $this->getHash($password),
		], $params);

		$uid = $userTable->useTimestamp()->insert($userData);

		$email = htmlentities(strtolower($email));

		if ($useEmailActivation) {
			$addRequest = $this->addRequest($uid, $email, "activation", $useEmailActivation);

			if ($addRequest['error']) {
				// @codeCoverageIgnoreStart
				$userTable->delete($uid);

				$return['message'] = $addRequest['message'];
				return $return;
				// @codeCoverageIgnoreEnd
			}

			$userTable->updateBy(['active' => 0], ['id' => $uid]);
		} else {
			$userTable->updateBy(['active' => 1], ['id' => $uid]);
		}

		$return['error'] = false;
		return $return;
	}

	/**
	 * Allows a user to delete their account
	 * secure with password before delete
	 *
	 * @param int    $uid
	 * @param string $password
	 * @return array{error: bool, message: string}
	 */
	public function secureDeleteAccount(int $uid, string $password)
	{
		$return['error'] = true;

		if ($this->isIPLocked()) {
			// @codeCoverageIgnoreStart
			$return['message'] = lang("Auth.user_blocked");
			// @codeCoverageIgnoreEnd
		} elseif (!$this->matchUserPassword($uid, $password)) {
			$return['message'] = lang("Auth.password_incorrect");

			$this->addAttempt('secureDeleteAccount::' . $return['message']);
		} else {
			$return = $this->deleteAccount($uid);
		}

		return $return;
	}

	/**
	 * Force delete account without password
	 *
	 * @param int $uid
	 * @return array{error: bool, message: string}
	 */
	public function deleteAccount(int $uid)
	{
		$userTable = DB::table($this->config->userTable);

		$userTable->delete($uid);

		$tblSession = DB::table($this->config->authSessionTable);

		$tblSession->deleteBy(['uid' => $uid]);

		$tblRequest = DB::table($this->config->authRequestTable);

		$tblRequest->deleteBy(['uid' => $uid]);

		$return['error']   = false;
		$return['message'] = lang("Auth.account_deleted");

		return $return;
	}

	/**
	 * Creates an activation entry and sends email to user
	 *
	 * @param int    $uid
	 * @param string $email
	 * @param string $type
	 * @param bool   $sendEmail
	 *
	 * @return array{error: bool, message?: string}
	 */
	protected function addRequest(int $uid, string $email, string $type, bool $sendEmail = true)
	{
		$return['error'] = true;

		$requestTypeExist = $type . '_exists';

		$reqTable = DB::table($this->config->authRequestTable);
		$request  = $reqTable->select('id, expire_date')
			->asArray()
			->findOneBy([
				'uid'  => $uid,
				'type' => $type,
			]);

		if (is_array($request)) {
			$expireDate  = strtotime($request['expire_date']);
			$currentDate = strtotime(date("Y-m-d H:i:s"));

			if ($currentDate < $expireDate) {
				$return['message'] = lang('Auth.' . $requestTypeExist);
				return $return;
			}

			$this->deleteRequest($request['id']);
		}

		$token  = $this->getRandomKey(self::TOKEN_LENGTH);
		$expire = date("Y-m-d H:i:s", strtotime($this->config->requestKeyExpiration));

		$requestId = $reqTable->insert([
			'uid'         => $uid,
			'token'       => $token,
			'expire_date' => $expire,
			'type'        => $type,
		]);

		if ($sendEmail) {
			$sendmailStatus = $this->sendMail($email, $type, $token);

			if ($sendmailStatus['error']) {
				$this->deleteRequest($requestId);

				$return['message'] = $sendmailStatus['message'];
				return $return;
			}
		}

		$return['error'] = false;

		return $return;
	}

	/**
	 * Get Token request from user
	 *
	 * @param int    $uid
	 * @param string $type
	 *
	 * @return string|null
	 */
	public function getUserRequestToken(int $uid, string $type)
	{
		$reqTable = DB::table($this->config->authRequestTable);
		$request  = $reqTable->select('token')
			->asObject()
			->findOneBy([
				'uid'  => $uid,
				'type' => $type,
			]);

		return is_object($request) ? $request->token : null;
	}

	/**
	 * Returns request data if key is valid
	 * @param string $key
	 * @param string $type
	 *
	 * @return array{error: bool, message?: string, id?: int, uid?: int}
	 */
	public function getRequest(string $key, string $type)
	{
		$return['error'] = true;

		$reqTable = DB::table($this->config->authRequestTable);

		$row = $reqTable->select('id, uid, expire_date')
			->asArray()
			->findOneBy([
				'token' => $key,
				'type'  => $type,
			]);

		if (!is_array($row)) {
			$return['message'] = lang('Auth.' . $type . 'key_incorrect');

			$this->addAttempt('getRequest::' . $return['message']);

			return $return;
		}

		$expireDate  = strtotime($row['expire_date']);
		$currentdate = strtotime(date("Y-m-d H:i:s"));

		if ($currentdate > $expireDate) {
			$this->deleteRequest($row['id']);

			$return['message'] = lang('Auth.' . $type . 'key_expired');

			$this->addAttempt('getRequest::' . $return['message']);

			return $return;
		}

		$return['error'] = false;
		$return['id']    = $row['id'];
		$return['uid']   = $row['uid'];

		return $return;
	}

	/**
	 * Delete request from database
	 *
	 * @param int $id
	 * @return bool
	 */
	protected function deleteRequest(int $id)
	{
		$reqTable = DB::table($this->config->authRequestTable);
		return $reqTable->delete($id);
	}

	/**
	 * Verifies that a password is greater than minimal length
	 *
	 * @param string $password
	 *
	 * @return array{error: bool, message?: string}
	 */
	protected function validatePassword(string $password)
	{
		$state['error'] = false;

		if (strlen($password) < (int) $this->config->passwordMinLength) {
			$state['error']   = true;
			$state['message'] = lang("Auth.password_short");

			return $state;
		}

		if ($this->config->validatePasswordStrength) {
			$zxcvbn = new Zxcvbn();

			if ($zxcvbn->passwordStrength($password)['score'] < intval($this->config->passwordMinScore)) {
				$state['error']   = true;
				$state['message'] = lang('Auth.password_weak');

				return $state;
			}
		}

		return $state;
	}

	/**
	 * Verifies that an email is valid
	 * @param string $email
	 *
	 * @return array{error: bool, message?: string}
	 */
	protected function validateEmail(string $email)
	{
		$state['error'] = true;

		if (strlen($email) < (int) $this->config->verifyEmailMinLength) {
			$state['message'] = lang('Auth.email_short', [$this->config->verifyEmailMinLength]);
			return $state;
		} elseif (strlen($email) > (int) $this->config->verifyEmailMaxLength) {
			$state['message'] = lang('Auth.email_long', [$this->config->verifyEmailMaxLength]);
			return $state;
		} elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
			$state['message'] = lang("Auth.email_invalid");
			return $state;
		}

		$state['error'] = false;

		return $state;
	}

	/**
	 * Allows a user to reset their password after requesting a reset key.
	 * @param string $key
	 * @param string $password
	 * @param string $repeatPassword
	 *
	 * @return array{error: bool, message: string}
	 */
	public function resetPass(string $key, string $password, string $repeatPassword)
	{
		$state['error'] = true;

		if ($this->isIPLocked()) {
			// @codeCoverageIgnoreStart
			$state['message'] = lang("Auth.user_blocked");
			// @codeCoverageIgnoreEnd
		} elseif (strlen($key) != self::TOKEN_LENGTH) {
			$state['message'] = lang("Auth.resetkey_invalid");
		} else {
			$validatePasswordState = $this->validatePassword($password);

			if ($validatePasswordState['error']) {
				$state['message'] = $validatePasswordState['message'];
			} elseif ($password !== $repeatPassword) {
				$state['message'] = lang("Auth.newpassword_nomatch");
			} else {
				$state['error'] = false;
			}
		}

		if (!$state['error']) {
			$error = true;

			$request = $this->getRequest($key, 'reset');

			if ($request['error']) {
				$state['message'] = $request['message'];
			} else {
				$user = $this->getUser($request['uid'], true);

				if (!$user) {
					// @codeCoverageIgnoreStart
					$this->deleteRequest($request['id']);

					$state['message'] = lang("Auth.system_error");

					$this->addAttempt('resetPass::' . $state['message']);
					// @codeCoverageIgnoreEnd
				} elseif (password_verify($password, $user['password'])) {
					$state['message'] = lang("Auth.newpassword_match");

					$this->addAttempt('resetPass::' . $state['message']);
				} else {
					$password = $this->getHash($password);

					$userTable = DB::table($this->config->userTable);

					$userTable->update($request['uid'], ['password' => $password]);

					$this->deleteRequest($request['id']);

					$error = false;

					$state['message'] = lang("Auth.password_reset");
				}
			}
			$state['error'] = $error;
		}

		return $state;
	}

	/**
	 * Recreates activation email for a given email
	 *
	 * @param string $email
	 *
	 * @return array{error: bool, message: string}
	 */
	public function resendActivation(string $email)
	{
		$state['error'] = true;

		if ($this->isIPLocked()) {
			$state['message'] = lang("Auth.user_blocked");
			return $state;
		}

		$validateEmail = $this->validateEmail($email);

		if ($validateEmail['error']) {
			$state['message'] = $validateEmail['message'];
			return $state;
		}

		$uid = $this->getUID($email);

		if (!$uid) {
			$state['message'] = lang("Auth.email_incorrect");

			$this->addAttempt('resendActivation::' . $state['message']);

			return $state;
		}

		$user = $this->getUser($uid);

		if ((bool) $user['active']) {
			$state['message'] = lang("Auth.already_activated");

			$this->addAttempt('resendActivation::' . $state['message']);

			return $state;
		}

		$addRequest = $this->addRequest($uid, $email, 'activation');

		if ($addRequest['error']) {
			$state['message'] = $addRequest['message'];

			$this->addAttempt('resendActivation::' . $state['message']);

			return $state;
		}

		$state['error']   = false;
		$state['message'] = lang("Auth.activation_sent");
		return $state;
	}

	/**
	 * Changes a user's password
	 *
	 * @param int    $uid
	 * @param string $currentPassword
	 * @param string $newPassword
	 * @param string $repeatNewPassword
	 *
	 * @return array{error: bool, message: string}
	 */
	public function changePassword(int $uid, string $currentPassword, string $newPassword, string $repeatNewPassword)
	{
		$return['error'] = true;

		if ($this->isIPLocked()) {
			$return['message'] = lang("Auth.user_blocked");
		} else {
			$validatePassword = $this->validatePassword($currentPassword);

			if ($validatePassword['error']) {
				$return['message'] = $validatePassword['message'];

				$this->addAttempt('changePassword::' . $return['message']);
			} else {
				$validatePassword = $this->validatePassword($newPassword);

				if ($validatePassword['error']) {
					$return['message'] = $validatePassword['message'];

					$this->addAttempt('changePassword::' . $return['message']);
				} elseif ($newPassword !== $repeatNewPassword) {
					$return['message'] = lang("Auth.newpassword_nomatch");

					$this->addAttempt('changePassword::' . $return['message']);
				} else {
					$return['error'] = false;
				}
			}
		}

		if (!$return['error']) {
			$return['error'] = true;

			$user = $this->getUser($uid, true);

			if (!$user) {
				$return['message'] = lang("Auth.account_not_found");

				$this->addAttempt('changePassword::' . $return['message']);
			} elseif (!password_verify($currentPassword, $user['password'])) {
				$return['message'] = lang("Auth.password_incorrect");

				$this->addAttempt('changePassword::' . $return['message']);
			} else {
				$return['error'] = false;
			}

			if (!$return['error']) {
				$newPassword = $this->getHash($newPassword);

				$userTable = DB::table($this->config->userTable);

				$userTable->update($uid, ['password' => $newPassword]);

				$return['message'] = lang("Auth.password_changed");
			}
		}

		return $return;
	}

	/**
	 * Changes a user's email
	 *
	 * @param int    $uid
	 * @param string $email
	 * @param string $password
	 *
	 * @return array{error: bool, message: string}
	 */
	public function changeEmail(int $uid, string $email, string $password)
	{
		$return['error'] = true;

		if ($this->isIPLocked()) {
			$return['message'] = lang("Auth.user_blocked");
		} elseif (!$this->matchUserPassword($uid, $password)) {
			$return['message'] = lang("Auth.password_incorrect");

			$this->addAttempt('changeEmail::' . $return['message']);
		} elseif ($this->isEmailTaken($email)) {
			$return['message'] = lang("Auth.email_taken", [$email]);

			$this->addAttempt('changeEmail::' . $return['message']);
		} else {
			$validateEmail = $this->validateEmail($email);

			if ($validateEmail['error']) {
				$return['message'] = $validateEmail['message'];
			} else {
				$return['error'] = false;
			}
		}

		if (!$return['error']) {
			$userTable = DB::table($this->config->userTable);

			$userTable->update($uid, ['email' => $email]);

			$return['message'] = lang("Auth.email_changed");
		}

		return $return;
	}

	/**
	 * Check if IP was locked out
	 * @return bool
	 */
	public function isIPLocked()
	{
		$ip = $this->getIp();

		$this->deleteExpiredAttempts($ip);

		$tblAttempts = DB::table($this->config->authAttemptTable);

		$attempts = $tblAttempts->where('ip', $ip)->findAll();

		return (is_array($attempts) && count($attempts) >= intval($this->config->attemptsBeforeLocked));
	}

	/**
	 * Adds an attempt to database
	 *
	 * @param string $note
	 *
	 * @return bool
	 */
	protected function addAttempt(string $note = '')
	{
		$ip = $this->getIp();

		$attemptExpireDate = date("Y-m-d H:i:s", strtotime($this->config->attackMitigationTime));

		$attempt = DB::table($this->config->authAttemptTable);

		return $attempt->insert([
			'ip'          => $ip,
			'expire_date' => $attemptExpireDate,
			'note'        => $note,
		]);
	}

	/**
	 * Deletes expired attempts from the database
	 *
	 * @param string $ip
	 * @return bool
	 */
	protected function deleteExpiredAttempts(string $ip = 'all')
	{
		$tblAttempts = DB::table($this->config->authAttemptTable);

		$tblAttempts->where('NOW() > expire_date', null, false);

		if ($ip !== 'all') {
			$tblAttempts->where('ip', $ip);
		}

		return $tblAttempts->delete();
	}

	/**
	 * Returns a random string of a specified length
	 * @param int $length
	 *
	 * @return string
	 */
	public function getRandomKey(int $length = self::TOKEN_LENGTH)
	{
		$dictionary = "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6";

		$dictionaryLength = strlen($dictionary);

		$key = '';

		for ($i = 0; $i < $length; $i++) {
			$key .= $dictionary[mt_rand(0, $dictionaryLength - 1)];
		}

		return $key;
	}

	/**
	 * Returns IP address
	 * @return string
	 *
	 * @codeCoverageIgnore
	 */
	protected function getIp()
	{
		if (getenv('HTTP_CLIENT_IP')) {
			$ipAddress = getenv('HTTP_CLIENT_IP');
		} elseif (getenv('HTTP_X_FORWARDED_FOR')) {
			$ipAddress = getenv('HTTP_X_FORWARDED_FOR');
		} elseif (getenv('HTTP_X_FORWARDED')) {
			$ipAddress = getenv('HTTP_X_FORWARDED');
		} elseif (getenv('HTTP_FORWARDED_FOR')) {
			$ipAddress = getenv('HTTP_FORWARDED_FOR');
		} elseif (getenv('HTTP_FORWARDED')) {
			$ipAddress = getenv('HTTP_FORWARDED');
		} elseif (getenv('REMOTE_ADDR')) {
			$ipAddress = getenv('REMOTE_ADDR');
		} else {
			$ipAddress = '127.0.0.1';
		}

		return $ipAddress;
	}

	/**
	 * Returns is user logged in
	 * @return bool
	 */
	public function isLogged()
	{
		if ($this->isAuthenticated === false) {
			$this->isAuthenticated = $this->checkSession($this->getCurrentSessionHash());
		}
		return $this->isAuthenticated;
	}

	/**
	 * Check if given password match with user's password
	 *
	 * @param int    $userid
	 * @param string $passwordChecked
	 * @return bool
	 */
	public function matchUserPassword(int $userid, string $passwordChecked)
	{
		$userTable = DB::table($this->config->userTable);

		$data = $userTable->find($userid);

		return is_array($data) ? password_verify($passwordChecked, $data['password']) : false;
	}

	/**
	 * Check if users password needs to be rehashed
	 * @param string $password
	 * @param string $hash
	 * @param int    $uid
	 * @return bool
	 */
	public function passwordVerifyWithRehash(string $password, string $hash, int $uid)
	{
		if (!password_verify($password, $hash)) {
			return false;
		}

		if (password_needs_rehash($hash, PASSWORD_DEFAULT, ['cost' => $this->config->bcryptCost])) {
			$hash = $this->getHash($password);

			$userTable = DB::table($this->config->userTable);
			$userTable->updateBy(['password' => $hash], ['id' => $uid]);
		}

		return true;
	}

	/**
	 * Send email via PHPMailer
	 *
	 * @param string $email
	 * @param string $type
	 * @param string $key
	 * @return array{error: bool, message?: string}
	 */
	public function sendMail(string $email, string $type, string $key)
	{
		helper('url');

		$return = [
			'error' => true,
		];

		if (!in_array($type, ['activation', 'reset'])) {
			$return['message'] = lang('Auth.unknown_mail_type');

			return $return;
		}

		// Get callback from config
		$callbackSendEmailFn = $this->config->sendMailCallback ?? null;

		$mailSubject = '';
		$mailMessage = '';

		if ($type == 'activation') {
			$mailSubject = lang('Auth.email_activation_subject', [$this->config->siteName]);
			$mailMessage = lang('Auth.email_activation_body', [site_url(), $this->config->siteActivationPage, $key]);
		} elseif ($type == 'reset') {
			$mailSubject = lang('Auth.email_reset_subject', [$this->config->siteName]);
			$mailMessage = lang('Auth.email_reset_body', [site_url(), $this->config->sitePasswordResetPage, $key]);
		}

		if (is_callable($callbackSendEmailFn)) {
			// Use the callback function to send the email
			try {
				$success = $callbackSendEmailFn([
					'fromEmail' => $this->config->siteEmail,
					'fromName'  => $this->config->siteName,
					'to'        => $email,
					'subject'   => $mailSubject,
					'message'   => $mailMessage,
				]);

				if ($success) {
					$return['error'] = false;
				} else {
					$return['message'] = lang('Auth.' . $type . '_email_not_sent'); // Or a more specific message from the callback
				}
			} catch (\Exception $e) {
				log_message('error', 'failed to send email using callback:' . $e->getMessage());
				// @codeCoverageIgnoreStart
				$return['message'] = lang('Auth.' . $type . '_email_not_sent'); // Or a more specific message from the callback
				// @codeCoverageIgnoreEnd
			}

			return $return;
		}

		$mail = \Config\Services::email();

		// Check configuration for custom SMTP parameters
		try {
			//Recipients
			$mail->setFrom($this->config->siteEmail, $this->config->siteName);
			$mail->setTo($email);

			// Use the pre-calculated subject and message
			$mail->setSubject($mailSubject);
			$mail->setMessage($mailMessage);

			if (!$mail->send()) {
				log_message('error', 'failed to send email using php mailer:' . $mail->printDebugger());
				// @codeCoverageIgnoreStart
				$return['message'] = lang('Auth.' . $type . '_email_not_sent');
				return $return;
				// @codeCoverageIgnoreEnd
			}

			$return['error'] = false;
		}
		// @codeCoverageIgnoreStart
		catch (\Exception $e) {
			$return['message'] = lang('Auth.' . $type . '_email_not_sent');
		}
		// @codeCoverageIgnoreEnd
		return $return;
	}

	/**
	 * Update userinfo for user with given id = $uid
	 * @param int   $uid
	 * @param array $params
	 *
	 * @return bool
	 */
	public function updateUser(int $uid, array $params)
	{
		$userTable = DB::table($this->config->userTable);

		return $userTable->save(array_merge($params, ['id' => $uid]));
	}

	/**
	 * Gets user data for a given UID
	 *
	 * @param int  $uid
	 * @param bool $withPassword
	 *
	 * @return array|false
	 */
	public function getUser(int $uid, bool $withPassword = false)
	{
		$userTable = DB::table($this->config->userTable);

		$data = $userTable->asArray()->find($uid);

		if (is_array($data)) {
			$data['uid'] = $uid;

			if (!$withPassword) {
				unset($data['password']);
			}
		}

		return $data ?? false;
	}

	/**
	 * Gets user data for a loginID
	 *
	 * @param string|int $loginID
	 * @param bool       $withPassword
	 *
	 * @return array|false
	 */
	public function getUserByLoginID($loginID, bool $withPassword = false)
	{
		$userTable = DB::table($this->config->userTable);

		$data = $userTable->asArray()->findOneBy([
			$this->config->loginID => $loginID,
		]);

		if (is_array($data)) {
			$data['uid'] = $data['id'];

			if (!$withPassword) {
				unset($data['password']);
			}
		}

		return $data ?? false;
	}

	/**
	 * Gets UID for a given email address, return int
	 *
	 * @param string $email
	 *
	 * @return int|false
	 */
	public function getUID(string $email)
	{
		$userTable = DB::table($this->config->userTable);

		$user = $userTable->asObject()->findOneBy(['email' => $email]);

		return is_object($user) ? (int) $user->id : false;
	}

	/**
	 * Returns current user UID if logged or FALSE otherwise.
	 *
	 * @return int
	 */
	public function getCurrentUID()
	{
		return (int) $this->getSessionUID($this->getCurrentSessionHash());
	}

	/**
	 * Returns current session hash
	 *
	 * @return string
	 */
	public function getCurrentSessionHash()
	{
		return isset($_COOKIE[$this->cookieConfig->cookiePrefix . $this->config->cookieName]) ? $_COOKIE[$this->cookieConfig->cookiePrefix . $this->config->cookieName] : '';
	}

	/**
	 * Retrieves the UID associated with a given session hash
	 *
	 * @param string $hash
	 *
	 * @return int|false
	 */
	public function getSessionUID(string $hash)
	{
		$sessTable = DB::table($this->config->authSessionTable);

		$session = $sessTable->select('uid')
			->asArray()
			->findOneBy(['hash' => $hash]);

		return isset($session['uid']) ? (int) $session['uid'] : false;
	}

	/**
	 * Gets user data for current user (from cookie/session_hash) and returns an array, password is not returned
	 * @return array|false
	 */
	public function getCurrentUser()
	{
		if ($uid = $this->getCurrentUID()) {
			$this->currentUser = $this->getUser($uid);
		}

		return $this->currentUser ?? false;
	}

	/**
	 * Get all user roles
	 *
	 * @return array
	 */
	public function getRoles()
	{
		$roleTable = DB::table($this->config->userRoleTable);

		$roles = $roleTable->where('active', 1)->findAll();

		return array_key_value($roles, ['id' => 'role']);
	}

	/**
	 * Get all user groups
	 *
	 * @return array
	 */
	public function getGroups()
	{
		$groupTable = DB::table($this->config->userGroupTable);

		$groups = $groupTable->where('active', 1)->findAll();

		return array_key_value($groups, ['id' => 'group']);
	}

	/**
	 * Check if current user has roles
	 *
	 * @param array $roles array of role_id or role name
	 *
	 * @return bool
	 */
	public function hasRoles(array $roles = [])
	{
		$hasRole = false;

		$user = $this->getCurrentUser();

		if ($user) {
			$role_id = (int) $user['role_id'];

			$hasValidRole = array_key_exists($role_id, $this->roles);

			if ($hasValidRole) {
				foreach ($roles as $role) {
					if (is_numeric($role)) {
						$hasRole = $hasRole || $role === $role_id;
					} else {
						$hasRole = $hasRole || $role === $this->roles[$role_id];
					}

					if ($hasRole) {
						break;
					}
				}
			}
		}

		return $hasRole;
	}

	/**
	 * Protect page with required roles only
	 *
	 * @param array  $roles
	 * @param string $namedRouteRedirect
	 *
	 * @codeCoverageIgnore
	 */
	public function requiredRoles(array $roles = [], string $namedRouteRedirect = 'forbidden-role')
	{
		if (!$this->hasRoles($roles)) {
			redirect()->route($namedRouteRedirect)->send();
			exit;
		}
	}

	/**
	 * Check if current user in spesific groups
	 *
	 * @param array $groups array of group_id or group name
	 *
	 * @return bool
	 */
	public function inGroups(array $groups = [])
	{
		$inGroup = false;

		$user = $this->getCurrentUser();

		if ($user) {
			$group_id = (int) $user['group_id'];

			$hasValidGroup = array_key_exists($group_id, $this->groups);

			if ($hasValidGroup) {
				foreach ($groups as $group) {
					if (is_numeric($group)) {
						$inGroup = $inGroup || $group === $group_id;
					} else {
						$inGroup = $inGroup || $group === $this->groups[$group_id];
					}

					if ($inGroup) {
						break;
					}
				}
			}
		}

		return $inGroup;
	}

	/**
	 * Protect page with required groups only
	 *
	 * @param array  $groups
	 * @param string $namedRouteRedirect
	 *
	 * @codeCoverageIgnore
	 */
	public function requiredGroups(array $groups = [], string $namedRouteRedirect = 'forbidden-group')
	{
		if (!$this->inGroups($groups)) {
			redirect()->route($namedRouteRedirect)->send();
			exit;
		}
	}

	/**
	 * Deletes expired sessions from the database
	 *
	 * @return bool
	 * @codeCoverageIgnore
	 */
	private function deleteExpiredSessions()
	{
		$tblSession = DB::table($this->config->authSessionTable);

		$tblSession->where('NOW() > expire_date', null, false);

		return $tblSession->delete();
	}

	/**
	 * Deletes expired requests from the database
	 *
	 * @return bool
	 * @codeCoverageIgnore
	 */
	private function deleteExpiredRequests()
	{
		$tblSession = DB::table($this->config->authRequestTable);

		$tblSession->where('NOW() > expire_date', null, false);

		return $tblSession->delete();
	}

	/**
	 * Daily cron job to remove expired data from the database
	 *
	 * @return void
	 * @codeCoverageIgnore
	 */
	public function cron()
	{
		$this->deleteExpiredAttempts();
		$this->deleteExpiredSessions();
		$this->deleteExpiredRequests();
	}
}