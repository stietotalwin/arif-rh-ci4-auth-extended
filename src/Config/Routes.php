<?php

$routes->group('forbidden', function ($routes)
{
	$routes->add('role', '\StieTotalWin\Auth\Controllers\Auth::deniedRole', ['as' => 'forbidden-role']);
	$routes->add('group', '\StieTotalWin\Auth\Controllers\Auth::deniedGroup', ['as' => 'forbidden-group']);
});