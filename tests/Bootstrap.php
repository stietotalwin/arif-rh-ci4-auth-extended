<?php

define('HOMEPATH', dirname(__DIR__) . DIRECTORY_SEPARATOR);
define('CONFIGPATH', HOMEPATH . 'vendor/codeigniter4/framework/app/Config/');
define('PUBLICPATH', HOMEPATH . 'vendor/codeigniter4/framework/public/');
define('TESTPATH', __DIR__ . DIRECTORY_SEPARATOR);
define('SUPPORTPATH', TESTPATH . 'Support' . DIRECTORY_SEPARATOR);
define('CI_DEBUG', true);

require HOMEPATH . 'vendor/codeigniter4/framework/system/Test/bootstrap.php';

$databaseConfig = config('Database');
$databaseConfig->defaultGroup = 'tests';
$db = db_connect('tests');
if ($db->getDatabase() !== 'stw_auth_ci4_test') {
	throw new RuntimeException('Refusing to rebuild a non-test Auth database.');
}

$forge = \Config\Database::forge('tests');
$db->disableForeignKeyChecks();
foreach ($db->listTables() as $table) {
	$forge->dropTable($table, true);
}
$db->enableForeignKeyChecks();

$migrations = \Config\Services::migrations(null, $db, false);
$migrations->setNamespace('StieTotalWin\\Auth')->latest();
\Config\Database::seeder('tests')->call(
	\StieTotalWin\Auth\Database\Seeds\AuthSeeder::class,
);
