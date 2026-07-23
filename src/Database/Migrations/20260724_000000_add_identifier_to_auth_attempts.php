<?php

namespace StieTotalWin\Auth\Database\Migrations;

class AddIdentifierToAuthAttempts extends \CodeIgniter\Database\Migration
{
	/**
	 * Adds the `identifier` column so login lockouts can be scoped to the
	 * (ip, identifier) pair instead of the shared public IP alone. Guarded so it
	 * is a no-op on fresh installs where the create migration already added it.
	 *
	 * @return void
	 */
	public function up()
	{
		$config = \CodeIgniter\Config\Factories::config('Auth');
		$table  = $config->authAttemptTable;

		if (! $this->db->fieldExists('identifier', $table)) {
			$this->forge->addColumn($table, [
				'identifier' => [
					'type'       => 'VARCHAR',
					'constraint' => '190',
					'null'       => true,
					'after'      => 'ip',
				],
			]);

			$this->forge->addKey(['ip', 'identifier']);
			$this->forge->processIndexes($table);
		}
	}

	/**
	 * @return void
	 */
	public function down()
	{
		$config = \CodeIgniter\Config\Factories::config('Auth');
		$table  = $config->authAttemptTable;

		if ($this->db->fieldExists('identifier', $table)) {
			$this->forge->dropColumn($table, 'identifier');
		}
	}
}
