<?php
/**
 * @file form.inc
 * Functions used to handle forms.
 */

// -----------------------------------------------------------------------------
// General

/**
 * Create a form for admin settings.
 *
 * @return
 *   Admin settings form.
 *
 * @see drupal_get_form()
 */
function yubikey_login_form_admin_settings() {
  $form['yubikey_login_require_otp_credentials'] = array(
    '#type' => 'checkbox',
    '#title' => t('Require one-time password (OTP) credentials'),
    '#description' => t('Require users to have one-time password credentials set for their accounts. With this setting enabled, existing users without credentials won\'t be required to submit a one-time password when logging in to allow backwards compatibility, but they will be notified to add their credentials when logged in. New users will be required to add their credentials during the registration process.'),
    '#default_value' => variable_get('yubikey_login_require_otp_credentials', FALSE));

  $form['yubikey_login_no_backup_codes_warning'] = array(
    '#type' => 'checkbox',
    '#title' => t('Warn about not having backup codes'),
    '#description' => t('Warn users when they have one-time password credentials but don\'t have any backup codes.'),
    '#default_value' => variable_get('yubikey_login_no_backup_codes_warning', TRUE));

  $form = system_settings_form($form);

  return $form;
}

/**
 * Modify the full login form.
 *
 * @param $form
 *   Form elements.
 * @param $form_state
 *   Form state.
 */
function yubikey_login_form_user_login_alter(&$form, &$form_state) {
  $all_users_have_credentials = variable_get('yubikey_login_all_users_have_credentials', FALSE);

  $field = array(
    '#type' => 'password',
    '#title' => t('YubiKey OTP'),
    '#maxlength' => 44,
    '#required' => $all_users_have_credentials);

  if ($all_users_have_credentials) {
    $field['#description'] = t('Touch the button on your YubiKey to enter a one-time password.');
  } else {
    $field['#description'] = t('Touch the button on your YubiKey to enter a one-time password or leave this field blank if you haven\'t set up YubiKey credentials for your account.');
  }

  yubikey_login_form_add_field_to_form($form, 'pass', 'yubikey-login-otp', $field);

  $form['#validate'][] = 'yubikey_login_form_login_form_validate';
}

/**
 * Modify the block login form.
 *
 * @param $form
 *   Form elements.
 * @param $form_state
 *   Form state.
 */
function yubikey_login_form_user_login_block_alter(&$form, &$form_state) {
  $all_users_have_credentials = variable_get('yubikey_login_all_users_have_credentials', FALSE);

  $field = array(
    '#type' => 'password',
    '#title' => t('YubiKey OTP'),
    '#size' => 15,
    '#maxlength' => 44,
    '#required' => $all_users_have_credentials);

  yubikey_login_form_add_field_to_form($form, 'pass', 'yubikey-login-otp', $field);

  $form['#validate'][] = 'yubikey_login_form_login_form_validate';
  $form['#submit'][] = 'yubikey_login_form_login_form_submit';
}

/**
 * Validate the login form.
 *
 * @param $form
 *   Form elements.
 * @param $form_state
 *   Form state.
 */
function yubikey_login_form_login_form_validate($form, &$form_state) {
  if (form_get_errors() || empty($form_state['uid'])) {
    return;
  }

  yubikey_login_load_libraries();

  $account_uid = $form_state['uid'];
  $account_name = user_load($account_uid)->name;
  $password = $form['pass']['#value'];
  $otp = $form['yubikey-login-otp']['#value'];

  // Allow users without credentials to login without a OTP for backwards
  // compatibility.
  if (empty($otp) && !yubikey_login_user_has_credentials($account_uid)) {
    return;
  }

  if (!yubikey_login_user_is_login_otp_attempt_allowed($account_uid)) {
    form_set_error('yubikey-login-otp', t('Sorry, there have been too many attempts with an incorrect YubiKey one-time password (OTP). Try again in awhile.'));
    watchdog('yubikey_login', 'Too many failed login attempts for %account_name with an incorrect YubiKey one-time password (OTP).', array('%account_name' => $account_name));
    return;
  }

  if (!yubilib\isOneTimePassword($otp, "modhex")) {
    yubikey_login_user_register_login_otp_attempt($account_uid);
    form_set_error('yubikey-login-otp', t('Invalid YubiKey one-time password (OTP).'));
    return;
  }

  try {
    $is_valid_otp = yubikey_login_user_check_otp($account_uid, $password, $otp);
  }
  catch (Exception $e) {
    yubikey_login_log_exception($e, $account_uid);
    drupal_set_message(t('Failed to check the one-time password. Please try again.'), 'error');
    return;
  }

  if (!$is_valid_otp) {
    yubikey_login_user_register_login_otp_attempt($account_uid);
    form_set_error('yubikey-login-otp', t('Invalid YubiKey one-time password (OTP).'));
  }
}

/**
 * Act on a successful login form submission.
 *
 * @param $form
 *   Form elements.
 * @param $form_state
 *   Form state.
 */
function yubikey_login_form_login_form_submit($form, &$form_state)  {
  $account_uid = $form_state['uid'];

  yubikey_login_user_clear_attempts($account_uid);
}

/**
 * Modify the password reset form.
 *
 * @param $form
 *   Form elements.
 * @param $form_state
 *   Form state.
 */
function yubikey_login_form_user_pass_alter(&$form, &$form_state) {
  $form['#validate'][] = 'yubikey_login_form_user_pass_validate';
}

/**
 * Validate the password reset form.
 *
 * @param $form
 *   Form elements.
 * @param $form_state
 *   Form state.
 */
function yubikey_login_form_user_pass_validate($form, &$form_state) {
  $account_uid = $form_state['values']['account']->uid;
  $has_credentials = yubikey_login_user_has_credentials($account_uid);

  if ($has_credentials) {
    $query = isset($form_state['input']['name']) ? array('name' => $form_state['input']['name']) : array();
    $backup_code_url = url('user/yubikey-login/use-backup-code', array('query' => $query));

    form_set_error('name', t('This account is protected by multi-factor authentication. <a href="@backup_code_url">Use a backup code</a> to regain access to it.', array('@backup_code_url' => $backup_code_url)));
  }
}

/**
 * Modify the user profile form.
 *
 * @param $form
 *   Form elements.
 * @param $form_state
 *   Form state.
 */
function yubikey_login_form_user_profile_form_alter(&$form, &$form_state) {
  $account_uid = $form['#user']->uid;
  $user_uid = $GLOBALS['user']->uid;
  $has_credentials = yubikey_login_user_has_credentials($account_uid);

  if (!$has_credentials) {
    return;
  }

  if ($user_uid != $account_uid) {
    $field = array(
      '#markup' => '<div class="description"><p>'.t('<strong>Warning</strong>: This user\'s YubiKey one-time password credentials will no longer work if the password is changed. For this reason, the credentials and the additional security they provide will be removed if you change the password.').'</p></div>');

    yubikey_login_form_add_field_to_form($form['account'], 'pass', 'yubikey-login-message', $field);
  }

  $form['#submit'][] = 'yubikey_login_form_user_profile_submit';
}

/**
 * Act on a successful user profile form submission.
 *
 * @param $form
 *   Form elements.
 * @param $form_state
 *   Form state.
 */
function yubikey_login_form_user_profile_submit($form, &$form_state) {
  $account_uid = $form_state['user']->uid;
  $account = $form_state['user'];
  $user_uid = $GLOBALS['user']->uid;
  $new_password = $form_state['input']['pass']['pass1'];

  if (!empty($new_password) && $user_uid != $account_uid) {
    yubikey_login_user_remove_user_data($account_uid);
    yubikey_login_send_notification('removed_credentials', $account);
    return;
  }

  // The old password is only available when editing one's own account.
  $old_password = $form_state['input']['current_pass'];

  if (!empty($old_password) && !empty($new_password)) {
    try {
      yubikey_login_user_reencrypt_secrets($account_uid, $old_password, $new_password);
    }
    catch (Exception $e) {
      $user_config_url = url("user/{$account_uid}/yubikey-login");

      yubikey_login_log_exception($e, $account_uid);
      drupal_set_message(t('Failed to update your YubiKey credentials using your new password. You should <a href="@user_config_url">change your credentials</a> immediately to avoid being locked out of your account.', array('@user_config_url' => $user_config_url)), 'error');
    }
  }
}

/**
 * Modify the user registration form.
 *
 * @param $form
 *   Form elements.
 * @param $form_state
 *   Form state.
 */
function yubikey_login_form_user_register_form_alter(&$form, &$form_state) {
  if (variable_get('user_email_verification', FALSE)) {
    return;
  }

  $yubikey_form = yubikey_login_form_user_yubikey_login($form, $form_state, $form["#user"]);
  $form = array_merge($form, $yubikey_form);
}

/**
 * Create the per-account YubiKey Login form.
 *
 * @param $form
 *   Form elements.
 * @param $form_state
 *   Form state.
 * @param $account
 *   User account.
 *
 * @return
 *   Per-account YubiKey Login form.
 *
 * @see drupal_get_form()
 */
function yubikey_login_form_user_yubikey_login($form, &$form_state, $account) {
  $uid = $account->uid;
  $yubikey_state = yubikey_login_form_yubikey_state_for_account($account);
  $is_new_account = empty($uid);

  if (empty($form['#user'])) {
    $form['#user'] = $account;
  }

  if (!$is_new_account) {
    $form['yubikey-login-default-submit'] = array(
      '#type' => 'submit',
      '#attributes' => array('class' => array('element-invisible')),
      '#value' => t('Save credentials'));

    $form['yubikey-login-backup-codes'] = yubikey_login_form_backup_codes_form($form, $form_state, $yubikey_state);
  }

  $form['yubikey-login-otp-credentials'] = yubikey_login_form_otp_credentials_form($form, $form_state, $yubikey_state);

  $form['#validate'][] = 'yubikey_login_form_user_yubikey_login_validate';
  $form['#submit'][] = 'yubikey_login_form_user_yubikey_login_submit';

  return $form;
}

/**
 * Validate the per-account YubiKey Login form.
 *
 * @param $form
 *   Form elements.
 * @param $form_state
 *   Form state.
 *
 * @see drupal_get_form()
 */
function yubikey_login_form_user_yubikey_login_validate($form, &$form_state) {
  $op = $form_state['input']['op'];
  $account = $form['#user'];
  $yubikey_state = yubikey_login_form_yubikey_state_for_account($account);

  if ($op == t('Create backup codes') || $op == t('Create new backup codes')) {
    yubikey_login_form_backup_codes_form_validate($form, $form_state, $yubikey_state);
  }
  elseif ($op == t('Save credentials') || $op == t('Create new account')) {
    yubikey_login_form_otp_credentials_form_validate($form, $form_state, $yubikey_state);
  }
  elseif ($op == t('Clear credentials...')) {
    yubikey_login_form_user_yubikey_login_clear_credentials_validate($form, $form_state, $yubikey_state);
  }
}

/**
 * Act on a successful per-account YubiKey Login form submission.
 *
 * @param $form
 *   Form elements.
 * @param $form_state
 *   Form state.
 *
 * @see drupal_get_form()
 */
function yubikey_login_form_user_yubikey_login_submit($form, &$form_state) {
  $op = $form_state['input']['op'];
  $account = $form['#user'];
  $yubikey_state = yubikey_login_form_yubikey_state_for_account($account);

  if ($op == t('Create backup codes') || $op == t('Create new backup codes')) {
    yubikey_login_form_backup_codes_form_submit($form, $form_state, $yubikey_state);
  }
  elseif ($op == t('Save credentials') || $op == t('Create new account')) {
    yubikey_login_form_otp_credentials_form_submit($form, $form_state, $yubikey_state);
  }
  elseif ($op == t('Clear credentials...')) {
    yubikey_login_form_user_yubikey_login_clear_credentials_submit($form, $form_state, $yubikey_state);
  }
}

/**
 * Create the backup codes subform.
 *
 * @param $form
 *   Form elements.
 * @param $form_state
 *   Form state.
 * @param $yubikey_state
 *   Current YubiKey Login state for the account.
 *
 * @return
 *   Backup codes subform.
 */
function yubikey_login_form_backup_codes_form($form, &$form_state, $yubikey_state) {
  $user_uid = $GLOBALS['user']->uid;
  $account_uid = $yubikey_state['account_uid'];
  $has_credentials = $yubikey_state['has_credentials'];
  $num_backup_codes = $yubikey_state['num_backup_codes'];
  $is_new_account = empty($account_uid);

  $form = array(
    '#type' => 'fieldset',
    '#title' => t('Backup Codes'),
    '#description' => t('Backup codes allow you to regain access to your account if you lose your YubiKey.'));

  if ($is_new_account) {
    $form['yubikey-login-message'] = array(
      '#markup' => '<p>'.t('You may create backup codes once you have created your account.').'</p>');

    return $form;
  }

  if ($user_uid != $account_uid) {
    $user_config_url = url("user/{$user_uid}/yubikey-login");

    $form['yubikey-login-message'] = array(
      '#markup' => '<p>'.t('You may only create backup codes for <a href="@user_config_url">your own account</a>.', array('@user_config_url' => $user_config_url)).'</p>');

    return $form;
  }

  if (!$has_credentials) {
    $form['yubikey-login-message'] = array(
      '#markup' => '<p>'.t('Your one-time password credentials need to be set before you can create backup codes.').'</p>');

    return $form;
  }

  if (!empty($form_state['yubikey-login-data']['backup-codes'])) {
    $backup_codes_text = '';

    for ($i = 1; $i <= YUBIKEY_LOGIN_NUM_BACKUP_CODES; $i++) {
      $backup_codes_text .= $form_state['yubikey-login-data']['backup-codes'][$i];
      $backup_codes_text .= "\n";
    }

    unset($form_state['yubikey-login-data']['backup-codes']);

    drupal_set_message(t('New backup codes have been created and can be viewed below. You will be unable to view them after leaving this page, so <strong>write them down or print them, and then keep them in a safe and secure place</strong>.'));

    $form['yubikey-login-backup-codes-message-a'] = array(
      '#markup' => '<p>'.t('Each of these backup codes can be used only once, but you can create new backup codes at any time.').'</p>');

    $form['yubikey-login-backup-codes-message-b'] = array(
      '#markup' => "<pre><code>{$backup_codes_text}</code></pre>");

    $form['yubikey-login-backup-codes-separator'] = array(
      '#markup' => '<hr />');
  }

  if ($num_backup_codes == 0) {
    $form['yubikey-login-message'] = array(
      '#markup' => '<p>'.t('<strong>You currently have no backup codes for your account</strong>. It\'s highly recommended to create them as soon as possible.').'</p>');

    $form['yubikey-login-create-backup-codes'] = array(
      '#type' => 'submit',
      '#value' => t('Create backup codes'));
  }
  else {
    $num_backup_codes_text = format_plural($num_backup_codes, '@count backup code', '@count backup codes');

    $form['yubikey-login-message'] = array(
      '#markup' => '<p>'.t('You currently have <strong>@num_backup_codes_text</strong> for your account.', array('@num_backup_codes_text' => $num_backup_codes_text)).'</p>');

    $form['yubikey-login-create-backup-codes'] = array(
      '#type' => 'submit',
      '#value' => t('Create new backup codes'));
  }

  return $form;
}

/**
 * Validate the backup codes subform.
 *
 * @param $form
 *   Form elements.
 * @param $form_state
 *   Form state.
 * @param $yubikey_state
 *   Current YubiKey Login state for the account.
 */
function yubikey_login_form_backup_codes_form_validate($form, &$form_state, $yubikey_state) {

}

/**
 * Handle a successful backup codes subform submission.
 *
 * @param $form
 *   Form elements.
 * @param $form_state
 *   Form state.
 * @param $yubikey_state
 *   Current YubiKey Login state for the account.
 */
function yubikey_login_form_backup_codes_form_submit($form, &$form_state, $yubikey_state) {
  $user_uid = $GLOBALS['user']->uid;
  $account_uid = $yubikey_state['account_uid'];
  $account = user_load($account_uid);
  $is_new_account = empty($account_uid);

  if ($is_new_account || $user_uid != $account_uid) {
    return;
  }

  $encoded_backup_codes = yubikey_login_user_set_backup_codes($account_uid);

  $form_state['yubikey-login-data']['backup-codes'] = $encoded_backup_codes;
  $form_state['rebuild'] = TRUE;
  $form_state['redirect'] = FALSE;

  yubikey_login_send_notification('set_backup_codes', $account);
}

/**
 * Create the one-time password credentials subform.
 *
 * @param $form
 *   Form elements.
 * @param $form_state
 *   Form state.
 * @param $yubikey_state
 *   Current YubiKey Login state for the account.
 *
 * @return
 *   One-time password credentials subform.
 */
function yubikey_login_form_otp_credentials_form($form, &$form_state, $yubikey_state) {
  $user_uid = $GLOBALS['user']->uid;
  $account_uid = $yubikey_state['account_uid'];
  $is_new_account = empty($account_uid);
  $has_credentials = $yubikey_state['has_credentials'];
  $public_identity = $yubikey_state['public_identity'];
  $are_credentials_required = variable_get('yubikey_login_require_otp_credentials', FALSE);
  $user_can_administer_users = user_access('administer users');

  $required = variable_get('yubikey_login_require_otp_credentials', FALSE);
  $required = $required && !$has_credentials;

  $personalization_link = 'https://www.yubico.com/products/services-software/personalization-tools/use/';

  $form = array(
    '#type' => 'fieldset',
    '#title' => t('One-Time Password Credentials'),
    '#description' => t('Adding one-time password (OTP) credentials allows you to further secure your account by requiring a one-time password as an additional <a href="https://en.wikipedia.org/wiki/Multi-factor_authentication">authentication factor</a> when logging in. Copy the credentials from the <i>Yubico OTP</i> section of the <a href="@personalization_link"><i>YubiKey Personalization Tool</i></a> or its log file.', array('@personalization_link' => $personalization_link)));
  $form['yubikey-login-public-identity'] = array(
    '#type' => 'textfield',
    '#title' => t('Public identity'),
    '#maxlength' => 47,
    '#size' => 17,
    '#required' => $required || $has_credentials,
    '#default_value' => $public_identity,
    '#attributes' => array('autocomplete' => 'off'));
  $form['yubikey-login-private-identity'] = array(
    '#type' => 'password',
    '#title' => t('Private identity'),
    '#maxlength' => 17,
    '#size' => 17,
    '#required' => $required && !$has_credentials,
    '#attributes' => array('autocomplete' => 'off'));
  $form['yubikey-login-secret-key'] = array(
    '#type' => 'password',
    '#title' => t('Secret key'),
    '#maxlength' => 47,
    '#size' => 47,
    '#required' => $required && !$has_credentials,
    '#attributes' => array('autocomplete' => 'off'));
  $form['yubikey-login-current-password'] = array(
    '#type' => 'password',
    '#title' => t('Current password'),
    '#size' => 25,
    '#access' => !$is_new_account,
    '#required' => $required && !$has_credentials,
    '#description' => t('Enter the current account password to update the credentials.'),
    '#attributes' => array('autocomplete' => 'off'));
  $form['yubikey-login-save-credentials'] = array(
    '#type' => 'submit',
    '#access' => !$is_new_account,
    '#value' => t('Save credentials'));
  $form['yubikey-login-clear-credentials'] = array(
    '#type' => 'submit',
    '#access' => $has_credentials && (!$are_credentials_required || $user_can_administer_users),
    '#value' => t('Clear credentials...'));

  if ($has_credentials) {
    $form['yubikey-login-private-identity']['#description'] = t('The current value is intentionally omitted.');
    $form['yubikey-login-secret-key']['#description'] = t('The current value is intentionally omitted.');
  }

  return $form;
}

/**
 * Validate the one-time password credentials subform.
 *
 * @param $form
 *   Form elements.
 * @param $form_state
 *   Form state.
 * @param $yubikey_state
 *   Current YubiKey Login state for the account.
 */
function yubikey_login_form_otp_credentials_form_validate($form, &$form_state, $yubikey_state) {
  yubikey_login_load_libraries();
  require_once DRUPAL_ROOT . '/' . variable_get('password_inc', 'includes/password.inc');

  $account_uid = $yubikey_state['account_uid'];
  $is_new_account = empty($account_uid);

  $public_identity = $form_state['input']['yubikey-login-public-identity'];
  $public_identity = yubikey_login_form_normalize_value($public_identity);
  $private_identity = $form_state['input']['yubikey-login-private-identity'];
  $private_identity = yubikey_login_form_normalize_value($private_identity);
  $secret_key = $form_state['input']['yubikey-login-secret-key'];
  $secret_key = yubikey_login_form_normalize_value($secret_key);

  if (strlen($private_identity) == 0 && strlen($secret_key) == 0) {
    if (strlen($public_identity) == 0) {
      return;
    }
    elseif ($public_identity == $yubikey_state['public_identity']) {
      return;
    }
  }

  if (!yubilib\isPublicIdentity($public_identity, "modhex")) {
    form_set_error('yubikey-login-public-identity', t('The Public identity field is not in the correct format.'));
  }

  if (!yubilib\isPrivateIdentity($private_identity, "hex")) {
    form_set_error('yubikey-login-private-identity', t('Private identity is not in the correct format.'));
  }

  if (!yubilib\isSecretKey($secret_key, "hex")) {
    form_set_error('yubikey-login-secret-key', t('The %title field is not in the correct format.', array('%title' => $form['yubikey-login-otp-credentials']['yubikey-login-secret-key']['#title'])));
  }

  if (!$is_new_account) {
    $password = $form_state['input']['yubikey-login-current-password'];
    $account = $form['#user'];

    if (!user_check_password($password, $account)) {
      form_set_error('yubikey-login-current-password', t('The current account password is incorrect.'));
    }
  }
}

/**
 * Handle a successful one-time password credentials subform submission.
 *
 * @param $form
 *   Form elements.
 * @param $form_state
 *   Form state.
 * @param $yubikey_state
 *   Current YubiKey Login state for the account.
 */
function yubikey_login_form_otp_credentials_form_submit($form, &$form_state, $yubikey_state) {
  $account_uid = $yubikey_state['account_uid'];
  $account = $form['#user'];
  $has_credentials = $yubikey_state['has_credentials'];

  // At this point, if the account was a new one, it's been created, so another
  // means of testing is required. Check whether the new account form password
  // exists.
  $is_new_account = !empty($form_state['input']['pass']['pass1']);

  $public_identity = $form_state['input']['yubikey-login-public-identity'];
  $public_identity = yubikey_login_form_normalize_value($public_identity);
  $private_identity = $form_state['input']['yubikey-login-private-identity'];
  $private_identity = yubikey_login_form_normalize_value($private_identity);
  $secret_key = $form_state['input']['yubikey-login-secret-key'];
  $secret_key = yubikey_login_form_normalize_value($secret_key);

  if ($public_identity == $yubikey_state['public_identity']) {
    if (strlen($private_identity) == 0 && strlen($secret_key) == 0) {
      drupal_set_message('No changes to one-time password credentials were necessary.');
      return;
    }
  }

  $new_credentials['public_identity'] = $public_identity;
  $new_credentials['private_identity'] = $private_identity;
  $new_credentials['secret_key'] = $secret_key;

  if ($is_new_account) {
    $password = $form_state['input']['pass']['pass1'];
  }
  else {
    $password = $form_state['input']['yubikey-login-current-password'];
  }

  try {
    yubikey_login_user_set_credentials($account_uid, $password, $new_credentials);
  }
  catch (Exception $e) {
    yubikey_login_log_exception($e, $account_uid);
    drupal_set_message(t('Failed to set your YubiKey credentials. Please try again.'), 'error');
    return;
  }

  if (!$is_new_account) {
    drupal_set_message('The one-time password credentials have been updated.');
  }

  $notification_type = $has_credentials ? 'updated_credentials' : 'added_credentials';
  yubikey_login_send_notification($notification_type, $account);
}

/**
 * Validate the clear credentials subform.
 *
 * @param $form
 *   Form elements.
 * @param $form_state
 *   Form state.
 * @param $yubikey_state
 *   Current YubiKey Login state for the account.
 */
function yubikey_login_form_user_yubikey_login_clear_credentials_validate($form, &$form_state, $yubikey_state) {

}

/**
 * Handle a successful clear credentials subform submission.
 *
 * @param $form
 *   Form elements.
 * @param $form_state
 *   Form state.
 * @param $yubikey_state
 *   Current YubiKey Login state for the account.
 */
function yubikey_login_form_user_yubikey_login_clear_credentials_submit($form, &$form_state, $yubikey_state) {
  $account_uid = $yubikey_state['account_uid'];
  $form_state['redirect'] = "user/{$account_uid}/yubikey-login/clear";
}

/**
 * Create the clear credentials confirmation form.
 *
 * @param $form
 *   Form elements.
 * @param $form_state
 *   Form state.
 *
 * @return
 *   Clear credentials confirmation form.
 *
 * @see drupal_get_form()
 */
function yubikey_login_form_user_yubikey_login_clear($form, &$form_state, $account) {
  $user_uid = $GLOBALS['user']->uid;
  $account_uid = $account->uid;
  $are_credentials_required = variable_get('yubikey_login_require_otp_credentials', FALSE);
  $user_can_administer_users = user_access('administer users');
  $has_credentials = yubikey_login_user_has_credentials($account_uid);

  if (!$has_credentials) {
    $form['yubikey-login-message'] = array(
      '#markup' => '<p>'.t('There are no credentials to clear.').'</p>');

    return $form;
  }

  if ($are_credentials_required && !$user_can_administer_users) {
    $form['yubikey-login-message'] = array(
      '#markup' => '<p>'.t('You aren\'t allowed to clear your YubiKey credentials because the site has been configured to require users to have them.').'</p>');

    return $form;
  }

  if ($user_uid != $account_uid && !$user_can_administer_users) {
    $user_config_url = url("user/{$user_uid}/yubikey-login");

    $form['yubikey-login-message'] = array(
      '#markup' => '<p>'.t('You can only clear your YubiKey credentials for <a href="@user_config_url">your own account</a>.', array('@user_config_url' => $user_config_url)).'</p>');

    return $form;
  }

  $form['#user'] = $account;

  $form['yubikey-login-account-uid'] = array(
    '#type' => 'hidden',
    '#value' => $account_uid);

  if (!$user_can_administer_users || $user_uid == $account_uid) {
    $form['yubikey-login-current-password'] = array(
      '#type' => 'password',
      '#title' => t('Current password'),
      '#size' => 25,
      '#required' => TRUE,
      '#description' => t('Enter the current account password to clear the credentials.'),
      '#attributes' => array('autocomplete' => 'off'));

    $form['#validate'][] = 'yubikey_login_form_user_yubikey_login_clear_validate';
  }

  $form = confirm_form($form, t('Are you sure you want to clear the YubiKey credentials for %account_name?', array('%account_name' => $account->name)), "user/{$account_uid}/yubikey-login", NULL, t('Clear credentials'));

  return $form;
}

/**
 * Validate a clear credentials confirmation form.
 *
 * @param $form
 *   Form elements.
 * @param $form_state
 *   Form state.
 *
 * @see drupal_get_form()
 */
function yubikey_login_form_user_yubikey_login_clear_validate($form, &$form_state) {
  if (!empty($form_state['input']['yubikey-login-current-password'])) {
    require_once DRUPAL_ROOT . '/' . variable_get('password_inc', 'includes/password.inc');

    $password = $form_state['input']['yubikey-login-current-password'];
    $account = $form['#user'];

    if (!user_check_password($password, $account)) {
      form_set_error('yubikey-login-current-password', t('The current account password is incorrect.'));
    }
  }
}

/**
 * Handle a successful clear credentials confirmation form submission.
 *
 * @param $form
 *   Form elements.
 * @param $form_state
 *   Form state.
 *
 * @see drupal_get_form()
 */
function yubikey_login_form_user_yubikey_login_clear_submit($form, &$form_state) {
  $account_uid = $form_state['input']['yubikey-login-account-uid'];
  $account = user_load($account_uid);
  $user_config_path = "user/{$account_uid}/yubikey-login";

  yubikey_login_user_remove_user_data($account_uid);

  $form_state['redirect'] = $user_config_path;

  drupal_set_message(t('Your credentials have been cleared.'));
  yubikey_login_send_notification('removed_credentials', $account);
}

/**
 * Create the form for using a backup code.
 *
 * @param $form
 *   Form elements.
 * @param $form_state
 *   Form state.
 *
 * @return
 *   Form for using a backup code.
 *
 * @see drupal_get_form()
 */
function yubikey_login_form_use_backup_code_form($form, &$form_state) {
  if (user_is_logged_in()) {
    $user_uid = $GLOBALS['user']->uid;
    $user_config_url = url("user/{$user_uid}/yubikey-login");

    $form['yubikey-login-message'] = array(
      '#markup' => '<p>'.t('You\'re already logged in. You can <a href="@user_config_url">manage your backup codes and other credentials</a> from your account settings.', array('@user_config_url' => $user_config_url)).'</p>');

    return $form;
  }

  $form['yubikey-login-message'] = array(
    '#markup' => '<p>'.t('If you\'ve forgotten your password or lost your YubiKey, enter your username or e-mail address and one of your backup codes to regain access to your account. Contact the site administrator if you haven\'t set up backup codes or have misplaced them.').'</p>');

  $form['yubikey-login-name'] = array(
    '#type' => 'textfield',
    '#title' => t('Username or e-mail address'),
    '#required' => TRUE,
    '#size' => 60,
    '#maxlength' => max(USERNAME_MAX_LENGTH, EMAIL_MAX_LENGTH),
    '#default_value' => isset($_GET['name']) ? $_GET['name'] : '',
    '#element_validate' => array('yubikey_login_form_validate_user_name_or_email'));

  $form['yubikey-login-backup-code'] = array(
    '#type' => 'textfield',
    '#title' => t('Backup code'),
    '#required' => TRUE,
    '#size' => 20,
    '#maxlength' => 20,
    '#element_validate' => array('yubikey_login_form_validate_friendly_backup_code'),
    '#attributes' => array('placeholder' => 'xxxx-xxxx-xxxx', 'autocomplete' => 'off'));

  $form['actions'] = array(
    '#type' => 'actions',
    'export' => array(
      '#type' => 'submit',
      '#value' => t('Log in')));

  $form['#validate'][] = 'yubikey_login_form_use_backup_code_form_validate';

  return $form;
}

/**
 * Validate the form for using a backup code.
 *
 * @param $form
 *   Form elements.
 * @param $form_state
 *   Form state.
 *
 * @see drupal_get_form()
 */
function yubikey_login_form_use_backup_code_form_validate($form, &$form_state) {
  if (form_get_errors()) {
    return;
  }

  $account_uid = $form_state['values']['uid'];
  $account_name = user_load($account_uid)->name;
  $friendly_backup_code = $form_state['input']['yubikey-login-backup-code'];
  $normalized_backup_code = yubikey_login_form_normalize_friendly_backup_code($friendly_backup_code);

  if (!yubikey_login_user_is_backup_code_attempt_allowed($account_uid)) {
    form_set_error('yubikey-login-backup-code', t('Sorry, there have been too many attempts with an incorrect backup code. Try again in awhile.'));
    watchdog('yubikey_login', 'Too many attempts with an incorrect backup code for %account_name.', array('%account_name' => $account_name));
    return;
  }

  $matched = yubikey_login_user_verify_valid_backup_code($account_uid, $normalized_backup_code);

  if ($matched) {
    $account = user_load($account_uid);
    yubikey_login_send_notification('used_backup_code', $account);
  }
  else {
    yubikey_login_user_register_backup_code_attempt($account_uid);
    form_set_error('yubikey-login-backup-code', t('Invalid backup code.'));
  }
}

/**
 * Handle a successful submission for the form for using a backup code.
 *
 * @param $form
 *   Form elements.
 * @param $form_state
 *   Form state.
 *
 * @see drupal_get_form()
 */
function yubikey_login_form_use_backup_code_form_submit($form, &$form_state) {
  global $user;

  $uid = $form_state['values']['uid'];
  $user = user_load($uid);

  $form_state['redirect'] = "user/{$uid}";
  user_login_finalize($form_state);
  yubikey_login_user_clear_attempts($uid);

  $user_config_url = url("user/{$uid}/yubikey-login");
  $num_backup_codes = yubikey_login_user_num_backup_codes($uid);
  $num_backup_codes_text = format_plural($num_backup_codes, '@count backup code', '@count backup codes');

  drupal_set_message(t('You logged in using one of your backup codes. You have <strong>@num_backup_codes_text</strong> remaining. You can <a href="@user_config_url">create new backup codes</a> at any time.', array('@num_backup_codes_text' => $num_backup_codes_text, '@user_config_url' => $user_config_url)));
}

// -----------------------------------------------------------------------------
// Generic form element validation

/**
 * Validate a username-or-email field.
 *
 * @param $element
 *   Form element.
 * @param $form_state
 *   Form state.
 * @param $form
 *   Form elements.
 */
function yubikey_login_form_validate_user_name_or_email($element, &$form_state, $form) {
  $name = trim($element['#value']);

  $users = user_load_multiple(array(), array('mail' => $name, 'status' => '1'));
  $account = reset($users);

  if (!isset($account->uid)) {
    $users = user_load_multiple(array(), array('name' => $name, 'status' => '1'));
    $account = reset($users);
  }

  if (isset($account->uid)) {
    form_set_value(array('#parents' => array('uid')), $account->uid, $form_state);
  }
  else {
    form_error($element, t('Sorry, %name is not recognized as a user name or an e-mail address.', array('%name' => $name)));
  }
}

/**
 * Validate a friendly-backup-code field.
 *
 * @param $element
 *   Form element.
 * @param $form_state
 *   Form state.
 * @param $form
 *   Form elements.
 */
function yubikey_login_form_validate_friendly_backup_code($element, &$form_state, $form) {
  $friendly_backup_code = $element['#value'];
  $normalized_backup_code = yubikey_login_form_normalize_friendly_backup_code($friendly_backup_code);

  if (strlen($normalized_backup_code) != 12) {
    form_error($element, t('The %title field is not in the correct format. It should look like <code>xxxx-xxxx-xxxx</code> and only contain the letters <i>A</i> through <i>F</i>, numbers, and hyphens.', array('%title' => $element['#title'])));
  }
}

// -----------------------------------------------------------------------------
// Helpers

/**
 * Add a form field to a form after another field.
 *
 * @param $form
 *   Form to add to.
 * @param $after
 *   Name of the field after which the field should be added.
 * @param $name
 *   Name of the field to add.
 * @param $field
 *   Field definition.
 */
function yubikey_login_form_add_field_to_form(&$form, $after, $name, $field) {
  $weight = 0;
  $field_weight = count($form);

  foreach ($form as $key => $value) {
    if ($key{0} != '#' && is_array($value)) {
      $form[$key]['#weight'] = $weight;
      $weight += 1;

      if ($key == $after) {
        $field_weight = $weight;
        $weight += 1;
      }
    }
  }

  $form[$name] = $field;
  $form[$name]['#weight'] = $field_weight;
}

/**
 * Normalize a form field value. For the purposes of this module, this removes
 * all whitespace.
 *
 * @param $value
 *   Form field value to normalize.
 *
 * @return
 *   Normalized form field value.
 */
function yubikey_login_form_normalize_value($value) {
  return preg_replace('/\\s+/', '', $value);
}

/**
 * Normalize a friendly backup code.
 *
 * @param $backup_code
 *   Backup code.
 *
 * @return
 *   Normalized backup code.
 */
function yubikey_login_form_normalize_friendly_backup_code($backup_code) {
  $normalized_backup_code = preg_replace('/[^a-fA-F0-9]+/', '', $backup_code);
  $normalized_backup_code = strtolower($normalized_backup_code);

  return $normalized_backup_code;
}

/**
 * Get the YubiKey Login state for an account for use in passing data between
 * forms.
 *
 * @param $account
 *   User account.
 *
 * @return
 *   YubiKey Login state.
 */
function yubikey_login_form_yubikey_state_for_account($account) {
  $uid = $account->uid;

  if (!empty($uid)) {
    $yubikey_state['account_uid'] = $uid;
    $yubikey_state['public_identity'] = yubikey_login_user_get_public_identity($uid);
    $yubikey_state['has_credentials'] = yubikey_login_user_has_credentials($uid);
    $yubikey_state['num_backup_codes'] = yubikey_login_user_num_backup_codes($uid);
  }
  else {
    $yubikey_state['account_uid'] = $uid;
    $yubikey_state['public_identity'] = "";
    $yubikey_state['has_credentials'] = FALSE;
    $yubikey_state['num_backup_codes'] = 0;
  }

  return $yubikey_state;
}
