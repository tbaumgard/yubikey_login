<?php
/**
 * @file user.inc
 * Functions used to manage user data.
 */

// -----------------------------------------------------------------------------
// General

/**
 * Setup YubiKey Login user data for a user.
 *
 * @param $uid
 *   User ID.
 *
 * @see yubikey_login_user_remove_user_data()
 */
function yubikey_login_user_setup_user_data($uid) {
	_yubikey_login_user_update_all_users_have_credentials_metadata();
}

/**
 * Remove YubiKey Login user data for a user.
 *
 * @param $uid
 *   User ID.
 *
 * @see yubikey_login_user_setup_user_data()
 */
function yubikey_login_user_remove_user_data($uid) {
  $query = db_delete('yubikey_login_credentials');
	$query->condition('uid', $uid);
	$query->execute();

  $query = db_delete('yubikey_login_backup_codes');
	$query->condition('uid', $uid);
	$query->execute();

	yubikey_login_user_clear_attempts($uid);
	_yubikey_login_user_update_all_users_have_credentials_metadata();
}

/**
 * Perform user data maintenance and cleanup.
 */
function yubikey_login_user_perform_data_maintenance() {
	$query = db_delete('yubikey_login_credentials');
	$query->where('uid NOT IN (SELECT uid FROM users)');
	$query->execute();

	$query = db_delete('yubikey_login_backup_codes');
	$query->where('uid NOT IN (SELECT uid FROM users)');
	$query->execute();

  $query = db_delete('yubikey_login_backup_codes');

  for ($i = 1; $i <= YUBIKEY_LOGIN_NUM_BACKUP_CODES; $i++) {
    $query->condition("hashed_backup_code_{$i}", NULL);
  }

  $query->execute();

	_yubikey_login_user_update_all_users_have_credentials_metadata();
}

// -----------------------------------------------------------------------------
// Credentials

/**
 * Determine whether a user has one-time password credentials.
 *
 * @param $uid
 *   User ID.
 *
 * @return
 *   TRUE if the user has one-time password credentials and FALSE otherwise.
 */
function yubikey_login_user_has_credentials($uid) {
  $query = db_select('yubikey_login_credentials', 'credentials');
  $query->addExpression('COUNT(*)', 'credentials_count');
  $query->condition('credentials.uid', $uid);
  $count = $query->execute()->fetchField();

  return $count > 0;
}

/**
 * Get the public identity for a user.
 *
 * @param $uid
 *   User ID.
 *
 * @return
 *   Public identity for the user or NULL if there is none.
 */
function yubikey_login_user_get_public_identity($uid) {
	$query = db_select('yubikey_login_credentials', 'credentials');
	$query->fields('credentials', array('public_identity'));
	$query->condition('credentials.uid', $uid);
	$public_identity = $query->execute()->fetchField();

  return $public_identity !== FALSE ? $public_identity : NULL;
}

/**
 * Set the one-time password credentials for a user.
 *
 * @param $uid
 *   User ID.
 * @param $password
 *   User password.
 * @param $credentials
 *   The credentials to update, identified by 'public_identity',
 *   'private_identity', and 'secret_key'
 *
 * @throw YubiKey_Login_Exception
 */
function yubikey_login_user_set_credentials($uid, $password, $credentials) {
  yubikey_login_load_libraries();

	$secrets['publicIdentity'] = $credentials['public_identity'];
	$secrets['privateIdentity'] = $credentials['private_identity'];
	$secrets['secretKey'] = $credentials['secret_key'];
	$secrets['counter'] = 0;

	$serialized_secrets = yubilib\prepareCredentials($secrets);
	$serialized_secrets = yubilib\serializeCredentials($serialized_secrets);

	try {
		$encrypted_credentials = Defuse\Crypto\Crypto::encryptWithPassword($serialized_secrets, $password, TRUE);
	}
  catch (Defuse\Crypto\Exception\CryptoException $e) {
    throw new YubiKey_Login_Exception(t('Failed to encrypt one-time password credentials'), $e);
  }

	$fields['public_identity'] = $credentials['public_identity'];
  $fields['encrypted_credentials'] = $encrypted_credentials;

  if (yubikey_login_user_has_credentials($uid)) {
    $query = db_update('yubikey_login_credentials');
		$query->fields($fields);
		$query->condition('uid', $uid);
		$query->execute();
  } else {
    $fields['uid'] = $uid;

    $query = db_insert('yubikey_login_credentials');
		$query->fields($fields);
		$query->execute();

		_yubikey_login_user_update_all_users_have_credentials_metadata();
  }
}

/**
 * Determine if a one-time password is valid for a user. If the one-time
 * password is valid, this function also changes the internal state to make the
 * one-time password no longer valid.
 *
 * @param $uid
 *   User ID.
 * @param $password
 *   User password.
 * @param $otp
 *   One-time password to check.
 *
 * @return
 *   TRUE if the one-time password is valid and FALSE otherwise.
 *
 * @throw YubiKey_Login_Exception
 */
function yubikey_login_user_check_otp($uid, $password, $otp) {
  yubikey_login_load_libraries();

  $query = db_select('yubikey_login_credentials', 'credentials');
  $query->fields('credentials');
  $query->condition('credentials.uid', $uid);
  $credentials = $query->execute()->fetchAssoc();

  $public_identity = $credentials['public_identity'];
	$encrypted_credentials = $credentials['encrypted_credentials'];

	try {
		$serialized_credentials = Defuse\Crypto\Crypto::decryptWithPassword($encrypted_credentials, $password, TRUE);
	}
  catch (Defuse\Crypto\Exception\CryptoException $e) {
    throw new YubiKey_Login_Exception(t('Failed to decrypt one-time password credentials'), $e);
  }

	$credentials = yubilib\deserializeCredentials($serialized_credentials);

	list($isValidOtp, $counter) = yubilib\validateOneTimePasswordLocally($otp, $credentials);

	if (!$isValidOtp) {
		return FALSE;
	}

  $credentials['counter'] = $counter;

  $serialized_credentials = yubilib\serializeCredentials($credentials);

	try {
		$encrypted_credentials = Defuse\Crypto\Crypto::encryptWithPassword($serialized_credentials, $password, TRUE);
	}
  catch (Defuse\Crypto\Exception\CryptoException $e) {
    throw new YubiKey_Login_Exception(t('Failed to encrypt one-time password credentials'), $e);
  }

  $query = db_update('yubikey_login_credentials');
  $query->fields(array('encrypted_credentials' => $encrypted_credentials));
  $query->condition('uid', $uid);
  $query->execute();

  return TRUE;
}

/**
 * Re-encrypt a user's one-time password credentials. This is useful when users
 * change their passwords.
 *
 * @param $uid
 *   User ID.
 * @param $old_password
 *   User's old password.
 * @param $new_password
 *   User's new password.
 *
 * @throw YubiKey_Login_Exception
 *
 * @see yubikey_login_user_has_credentials()
 */
function yubikey_login_user_reencrypt_secrets($uid, $old_password, $new_password) {
  yubikey_login_load_libraries();

  $query = db_select('yubikey_login_credentials', 'credentials');
  $query->fields('credentials', array('encrypted_credentials'));
  $query->condition('credentials.uid', $uid);
  $encrypted_credentials = $query->execute()->fetchField();

  try {
    $secrets = Defuse\Crypto\Crypto::decryptWithPassword($encrypted_credentials, $old_password, TRUE);
    $encrypted_credentials = Defuse\Crypto\Crypto::encryptWithPassword($secrets, $new_password, TRUE);
  }
  catch (Defuse\Crypto\Exception\CryptoException $e) {
    throw new YubiKey_Login_Exception(t('Failed to re-encrypt the one-time password credentials'), $e);
  }

  $query = db_update('yubikey_login_credentials');
  $query->fields(array('encrypted_credentials' => $encrypted_credentials));
  $query->condition('uid', $uid);
  $query->execute();
}

// -----------------------------------------------------------------------------
// Backup Codes

/**
 * Determine how many backup codes a user has.
 *
 * @param $uid
 *   User ID.
 *
 * @return
 *   TRUE if the user has backup codes and FALSE otherwise.
 */
function yubikey_login_user_num_backup_codes($uid) {
	_yubikey_login_user_clear_old_backup_code_data($uid);

  $query = db_select('yubikey_login_backup_codes', 'backup_codes');
  $query->fields('backup_codes');
  $query->condition('backup_codes.uid', $uid);
  $fields = $query->execute()->fetchAssoc();

	if (empty($fields)) {
		return 0;
	}

	$num_backup_codes = 0;

	for ($i = 1; $i <= YUBIKEY_LOGIN_NUM_BACKUP_CODES; $i++) {
    $hashed_backup_code_key = "hashed_backup_code_{$i}";

		if ($fields[$hashed_backup_code_key] !== NULL) {
			$num_backup_codes += 1;
		}
	}

	return $num_backup_codes;
}

/**
 * Generate and set the backup codes for a user.
 *
 * @param $uid
 *   User ID.
 *
 * @return
 *   Generated backup codes encoded in hex.
 */
function yubikey_login_user_set_backup_codes($uid) {
  yubikey_login_load_libraries();

  $query = db_delete('yubikey_login_backup_codes');
  $query->condition('uid', $uid);
  $query->execute();

  $fields['uid'] = $uid;
	$encoded_backup_codes = array();

	for ($i = 1; $i <= YUBIKEY_LOGIN_NUM_BACKUP_CODES; $i++) {
    $hashed_backup_code_key = "hashed_backup_code_{$i}";

		$backup_code = random_bytes(6);
    $hashed_backup_code = password_hash($backup_code, PASSWORD_DEFAULT);
		$encoded_backup_code = Defuse\Crypto\Encoding::binToHex($backup_code);

		$friendly_backup_code = substr($encoded_backup_code, 0, 4) . '-';
		$friendly_backup_code .= substr($encoded_backup_code, 4, 4) . '-';
		$friendly_backup_code .= substr($encoded_backup_code, 8, 4);

		$fields[$hashed_backup_code_key] = $hashed_backup_code;
		$encoded_backup_codes[$i] = $friendly_backup_code;
	}

	$query = db_insert('yubikey_login_backup_codes');
	$query->fields($fields);
	$query->execute();

	return $encoded_backup_codes;
}

/**
 * Verify a backup code and remove it if it's valid.
 *
 * @param $uid
 *   User ID.
 * @param $encoded_backup_code
 *   Backup code encoded in hex.
 *
 * @return
 *   TRUE if the backup code is valid and FALSE otherwise.
 */
function yubikey_login_user_verify_valid_backup_code($uid, $encoded_backup_code) {
  yubikey_login_load_libraries();
	_yubikey_login_user_clear_old_backup_code_data($uid);

  $query = db_select('yubikey_login_backup_codes', 'backup_codes');
  $query->fields('backup_codes');
  $query->condition('backup_codes.uid', $uid);
  $fields = $query->execute()->fetchAssoc();

	if (empty($fields)) {
		return FALSE;
	}

	$binary_backup_code = Defuse\Crypto\Encoding::hexToBin($encoded_backup_code);
  $matched_backup_code_key = NULL;

  for ($i = 1; $i <= YUBIKEY_LOGIN_NUM_BACKUP_CODES; $i++) {
    $hashed_backup_code_key = "hashed_backup_code_{$i}";
    $hashed_backup_code = $fields[$hashed_backup_code_key];

    if (empty($hashed_backup_code)) {
      continue;
    }

    if (!password_verify($binary_backup_code, $hashed_backup_code)) {
      continue;
    }

    $matched_backup_code_key = $hashed_backup_code_key;
    break;
  }

  if ($matched_backup_code_key !== NULL) {
    $query = db_update('yubikey_login_backup_codes');
    $query->fields(array($matched_backup_code_key => NULL));
    $query->condition('uid', $uid);
    $query->execute();
  }

  return $matched_backup_code_key !== NULL;
}

// -----------------------------------------------------------------------------
// Flood control

/**
 * Determine if a login attempt with a one-time password is allowed.
 *
 * @param $uid
 *   User ID.
 *
 * @return
 *   TRUE if the attempt is allowed and FALSE otherwise.
 */
function yubikey_login_user_is_login_otp_attempt_allowed($uid) {
	$uid_window = YUBIKEY_LOGIN_FLOOD_UID_WINDOW;
	$uid_threshold = YUBIKEY_LOGIN_FLOOD_UID_THRESHOLD;
	$ip_window = YUBIKEY_LOGIN_FLOOD_IP_WINDOW;
	$ip_threshold = YUBIKEY_LOGIN_FLOOD_IP_THRESHOLD;

	if (!flood_is_allowed('yubikey_login_login_otp_ip', $ip_threshold, $ip_window)) {
		return FALSE;
	}

	return flood_is_allowed('yubikey_login_login_otp_uid', $uid_threshold, $uid_window, $uid);
}

/**
 * Register a login attempt with a one-time password.
 *
 * @param $uid
 *   User ID.
 */
function yubikey_login_user_register_login_otp_attempt($uid) {
	$uid_window = YUBIKEY_LOGIN_FLOOD_UID_WINDOW;
	$ip_window = YUBIKEY_LOGIN_FLOOD_IP_WINDOW;

	flood_register_event('yubikey_login_login_otp_ip', $ip_window);
	flood_register_event('yubikey_login_login_otp_uid', $uid_window, $uid);
}

/**
 * Determine if a backup code attempt is allowed.
 *
 * @param $uid
 *   User ID.
 *
 * @return
 *   TRUE if the attempt is allowed and FALSE otherwise.
 */
function yubikey_login_user_is_backup_code_attempt_allowed($uid) {
	$uid_window = YUBIKEY_LOGIN_FLOOD_UID_WINDOW;
	$uid_threshold = YUBIKEY_LOGIN_FLOOD_UID_THRESHOLD;
	$ip_window = YUBIKEY_LOGIN_FLOOD_IP_WINDOW;
	$ip_threshold = YUBIKEY_LOGIN_FLOOD_IP_THRESHOLD;

	if (!flood_is_allowed('yubikey_login_backup_code_ip', $ip_threshold, $ip_window)) {
		return FALSE;
	}

	return flood_is_allowed('yubikey_login_backup_code_uid', $uid_threshold, $uid_window, $uid);
}

/**
 * Register a backup code attempt.
 *
 * @param $uid
 *   User ID.
 */
function yubikey_login_user_register_backup_code_attempt($uid) {
	$uid_window = YUBIKEY_LOGIN_FLOOD_UID_WINDOW;
	$ip_window = YUBIKEY_LOGIN_FLOOD_IP_WINDOW;

	flood_register_event('yubikey_login_backup_code_ip', $ip_window);
	flood_register_event('yubikey_login_backup_code_uid', $uid_window, $uid);
}

/**
 * Register a login and backup code attempts.
 *
 * @param $uid
 *   User ID.
 */
function yubikey_login_user_clear_attempts($uid) {
	// Only clear the UID attempts since a successful attempt from one client
	// behind an IP doesn't mean there aren't other malicious clients.
	flood_clear_event('yubikey_login_login_otp_uid', $uid);
	flood_clear_event('yubikey_login_backup_code_uid', $uid);
}

// -----------------------------------------------------------------------------
// Internal helpers

/**
 * Update the cached metadata for whether all users have credentials or not.
 */
function _yubikey_login_user_update_all_users_have_credentials_metadata() {
  $query = db_select('users', 'users');
  $query->addExpression('COUNT(*)', 'user_count');
  $user_count = $query->execute()->fetchField();

  $query = db_select('yubikey_login_credentials', 'credentials');
  $query->addExpression('COUNT(*)', 'credentials_count');
  $credentials_count = $query->execute()->fetchField();

	// Need to subtract one because there's row for anonymous users at uid = 0.
	$all_users_have_credentials = (bool) ($credentials_count == ($user_count - 1));

	variable_set('yubikey_login_all_users_have_credentials', $all_users_have_credentials);
}

/**
 * Remove empty backup code rows for a user.
 *
 * @param $uid
 *   User ID.
 */
function _yubikey_login_user_clear_old_backup_code_data($uid) {
  $query = db_delete('yubikey_login_backup_codes');
  $query->condition('uid', $uid);

  for ($i = 1; $i <= YUBIKEY_LOGIN_NUM_BACKUP_CODES; $i++) {
    $query->condition("hashed_backup_code_{$i}", NULL);
  }

  $query->execute();
}
