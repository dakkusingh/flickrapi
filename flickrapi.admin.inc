<?php

/**
 * @file
 * Admin settings form and OAuth authentication integration
 */

/**
 * Admin settings form
 */
function flickrapi_admin_settings() {
  $form = array();

  $form['flickrapi_api_key'] = array(
    '#type' => 'textfield',
    '#title' => t('API Key'),
    '#required' => TRUE,
    '#default_value' => variable_get('flickrapi_api_key', ''),
    '#description' => t('API Key from Flickr. !link', array(
      '!link' => l(
        t('Get one!'),
        'http://www.flickr.com/services/apps/by/me'
      ))
    ),
  );

  $form['flickrapi_api_secret'] = array(
    '#type' => 'textfield',
    '#title' => t('API Shared Secret'),
    '#required' => TRUE,
    '#default_value' => variable_get('flickrapi_api_secret', ''),
    '#description' => t("API key's secret from Flickr."),
  );

  $auth_token = variable_get('flickrapi_api_auth_token', '');
  if (empty($auth_token)) {
    $form['flickr_api_verified'] = array(
      '#markup' => t('<label>OAuth verification status</label> Not verified. Save this settings form to verify your credentials.'),
    );
  }
  else {
    $form['flickr_api_verified'] = array(
      '#markup' => t('<label>OAuth verification status</label> Verified. !delete', array('!delete' => l(t('Delete access token'), 'admin/config/media/flickrapi/clear'))),
    );
  }

  $times = array(
    900, 1800, 2700, 3600, 7200, 10800, 14400, 18000, 21600, 43200, 86400,
  );
  $ageoptions = drupal_map_assoc($times, 'format_interval');

  $form['advanced'] = array(
    '#type' => 'fieldset',
    '#title' => t('Advanced settings'),
    '#collapsible' => TRUE,
    '#collapsed' => (
      variable_get('flickrapi_access_permissions', array('read')) == 'read' &&
      variable_get('flickrapi_cache_duration', array('read')) == 3600 &&
      variable_get('flickrapi_cache_path', array('read')) == '/tmp'
    ) ? TRUE : FALSE,
  );

  $form['advanced']['flickrapi_access_permissions'] = array(
    '#type' => 'radios',
    '#title' => t('Flickr access permissions'),
    '#options' => array(
      'read' => t('Read only (default)'),
      'write' => t('Read & Write'),
      'delete' => t('Read, Write & Delete'),
    ),
    '#description' => t('If you change the access permissions after authentication, you need to re-authenticate your website.'),
    '#default_value' => variable_get('flickrapi_access_permissions', array('read')),
  );

  $form['advanced']['flickrapi_cache_duration'] = array(
    '#type' => 'select',
    '#title' => t('Update interval'),
    '#options' => $ageoptions,
    '#default_value' => variable_get('flickrapi_cache_duration', 3600),
    '#description' => t('The refresh interval indicating how often you want to check cached Flickr API calls are up to date.'),
  );

  $form['advanced']['flickrapi_cache_path'] = array(
    '#title' => t('Flickr Cache Path'),
    '#required' => TRUE,
    '#description' => t('Location on server file system where results of Flickr API calls can be cached.'),
    '#type' => 'textfield',
    '#default_value' => variable_get('flickrapi_cache_path', '/tmp'),
  );

  $form['#validate'][] = 'flickrapi_admin_settings_validate';
  $form['#submit'][] = 'flickrapi_admin_settings_submit';
  return system_settings_form($form);
}

/**
 * Implements hook_form_alter().
 *
 * If the API key has not been validated yet,
 * change the button text on the admin form.
 */
function flickrapi_form_flickrapi_admin_settings_alter(&$form, &$form_state) {
  $auth_token = variable_get('flickrapi_api_auth_token', '');
  if (empty($auth_token)) {
    $form['actions']['submit']['#value'] = t('Validate using OAuth');
  }
}

/**
 * Validator for the admin settings form.
 */
function flickrapi_admin_settings_validate($form, &$form_state) {
  $key = trim($form_state['values']['flickrapi_api_key']);
  $secret = trim($form_state['values']['flickrapi_api_secret']);
  $cache_dir = $form_state['values']['flickrapi_cache_path'];

  if ($key && (preg_match('/^[A-Fa-f\d]{32}$/', $key) != 1)) {
    form_set_error('flickrapi_api_key', t('This does not appear to be a Flickr API key.'));
  }

  if ($secret && (preg_match('/^[A-Fa-f\d]{16}$/', $secret) != 1)) {
    form_set_error('flickrapi_api_secret', t('This does not appear to be a Flickr API secret.'));
  }

  if (!file_prepare_directory($cache_dir)) {
    form_set_error('flickrapi_cache_path', t('Folder does not exist or it is not writable.'));
  }
}

/**
 * Submit handler for the admin settings form.
 */
function flickrapi_admin_settings_submit($form, &$form_state) {
  // If the Access Permissions have changed, we need to re-authenticate.
  if ($perm_element = $form_state['complete form']['advanced']['flickrapi_access_permissions']) {
    if ($perm_element['#value'] != $perm_element['#default_value']) {
      variable_del('flickrapi_api_auth_token');
    }
  }

  // Validate the credentials on Flickr.
  $auth_token = variable_get('flickrapi_api_auth_token', '');
  if (empty($auth_token)) {
    $form_state['redirect'] = 'admin/config/media/flickrapi/authenticate';
  }
}

/**
 * Fetch a token from Flickr using the key & secret the user entered.
 *
 * This functions handles:
 *   - Signing Requests
 *   - Getting a Request Token
 *   - Getting the User Authorization
 * See: http://www.flickr.com/services/api/auth.oauth.html
 */
function flickrapi_oauth_authenticate() {
  module_load_include('module', 'oauth_common');
  $callback = url('admin/config/media/flickrapi/authenticate', array('absolute' => TRUE));

  // If the OAuth verifier token is already returned by Flickr, verify it.
  if (!empty($_GET['oauth_verifier'])) {
    flickrapi_oauth_token_verify();
  }
  else {
    // Set up a new OAuth Consumer and Client if it cannot be loaded.
    $consumer = DrupalOAuthConsumer::load(variable_get('flickrapi_api_key', ''), FALSE);
    if (!$consumer) {
      $consumer = new DrupalOAuthConsumer(variable_get('flickrapi_api_key', ''), variable_get('flickrapi_api_secret', ''));
      $consumer->write();
    }
    $sig_method = DrupalOAuthClient::signatureMethod();
    $client = new DrupalOAuthClient($consumer, NULL, $sig_method);

    $request_token = $client->getRequestToken('http://www.flickr.com/services/oauth/request_token', array(
      'callback' => $callback)
    );
    $request_token->write();

    $auth_url = $client->getAuthorizationUrl(
      'http://www.flickr.com/services/oauth/authorize',
       array(
        'callback' => $callback,
        'params' => array(
          'perms' => variable_get('flickrapi_access_permissions', array('read'))
        ),
      )
    );

    // Send the user to the Flickr page which redirects
    // back to the Drupal site after accepting.
    drupal_goto($auth_url);
  }
}

/**
 * Verification callback to check the token we received from Flickr
 *
 * Handles the last step in the authentication proces:
 *   - Exchanging the Request Token for an Access Token
 * See http://www.flickr.com/services/api/auth.oauth.html
 */
function flickrapi_oauth_token_verify() {
  module_load_include('module', 'oauth_common');
  $consumer = DrupalOAuthConsumer::load(variable_get('flickrapi_api_key', ''), FALSE);
  $request_token = DrupalOAuthToken::loadByKey($_GET['oauth_token'], $consumer, OAUTH_COMMON_TOKEN_TYPE_REQUEST);

  $client = new DrupalOAuthClient($consumer, $request_token);
  $access_token = $client->getAccessToken('http://www.flickr.com/services/oauth/access_token', array(
    'verifier' => $_GET['oauth_verifier'])
  );

  variable_set('flickrapi_api_auth_token', $access_token);
  $request_token->delete();

  drupal_set_message(t('Succesfully verified'));
  drupal_goto('admin/config/media/flickrapi');
}

/**
 * Delete locally saved OAuth token.
 */
function flickrapi_oauth_clear() {
  drupal_set_message(t('Flickr authentication token is deleted.'));
  variable_del('flickrapi_api_auth_token');
  drupal_goto('admin/config/media/flickrapi');
}
