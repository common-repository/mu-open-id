<?php
/*
Plugin Name: OpenID Server
Plugin URI: http://automattic.com/code/openidserver/
Description: An OpenID server, so WP users can use their blog as an OpenID.
Author: Automattic
Version: 0.2
Author URI: http://automattic.com/
*/

define('OPENIDSERVER_DEBUG_MESSAGES', false);

function openidserver_is_enabled() {
	return (
		isset($_REQUEST['openidserver']) &&
		$_REQUEST['openidserver'] == '1'
	);
}

if (openidserver_is_enabled()) {
	/*
	Horrible include hack. The JanRain OpenID library is designed to be 
	installed using PEAR and expects 'Auth/' to be on the PHP include path. 
	Some of the files in the library have their own include() statements based
	on that assumption. To get the library working without modifying the files
	themselves (and hence making it harder to upgrade the library later) we
	temporarily alter the include path, then change it back afterwards.
	*/
	$old_include_path = set_include_path(dirname(__FILE__) . '/php-openid');
	require_once('Auth/OpenID/Interface.php');
	require_once('Auth/OpenID.php');
	require_once('Auth/OpenID/FileStore.php');
	require_once('Auth/OpenID/Server.php');
	require_once('Auth/OpenID/BigMath.php');
	set_include_path($old_include_path);
}

add_action('wp_head', 'openidserver_link_rel_tags');
add_action('admin_menu', 'openidserver_setup_menu');
add_action('init', 'openidserver_init');
add_action('admin_notices', 'openidserver_admin_show_pending');
add_action('wp_login', 'openidserver_login_intercept');

function openidserver_setup_menu() {
	add_submenu_page(
		'options-general.php', 'OpenID', 'OpenID', 10, 'openidserver',
		'openidserver_admin'
	);
}

function openidserver_init() {
	// Short-circuit WP if this is an OpenID server request
	if (openidserver_is_enabled()) {
		openidserver_server();
		exit;
	}
}

function openidserver_admin_show_pending() {
	$pending = openidserver_get_pending_request();
	if ($pending && $pending['site_url'] == get_option('siteurl')) {
		$continue_url = htmlspecialchars($pending['continue_url']);
		$trust_root = htmlspecialchars($pending['trust_root']);
		echo '<div class="updated"><p>Now that you are signed in, you can '.
			 "<a href='{$continue_url}'>".
			 "continue signing in to <strong>{$trust_root}</strong> " .
			 'with your OpenID</a>.</p></div>';
	}
}

function openidserver_link_rel_tags() {
	if (is_home()) {
		echo '<link rel="openid.server" href="' . 
			get_option('siteurl') . '/?openidserver=1" />';
	}
}

function openidserver_login_intercept($username) {
	/*
	When a user logs in we need to check if they have a pending OpenID request 
	by looking for a 'openidserver_pending' cookie. If the cookie is set we 
	need to redirect them straight to their dashboard rather than the homepage 
	or their own blog. This is so we can show them the 'continue signing in to 
	$blah' link.
	*/
	if (openidserver_has_pending_request()) {
		$pending = openidserver_get_pending_request();
		header('Location: '.$pending['site_url'] . '/wp-admin/');
		exit;
	}
}

function openidserver_openid_for_current_site() {
	return get_option('siteurl') . '/';
}

function openidserver_is_trusted($identity, $trust_root) {
	$trust_root = trim($trust_root);
	$trusted_roots = get_option('openidserver_trusted_roots');
	if (!$trusted_roots) {
		return false;
	}
	return in_array($trust_root, $trusted_roots);
}

function openidserver_add_trust_root($trust_root) {
	$trust_root = trim($trust_root);
	$trusted_roots = openidserver_get_trusted_roots();
	if (in_array($trust_root, $trusted_roots)) {
		return; // Don't add duplicate entries
	}
	$trusted_roots[] = $trust_root;
	update_option('openidserver_trusted_roots', $trusted_roots);
}

function openidserver_remove_trust_root_by_md5($md5) {
	$trusted_roots = openidserver_get_trusted_roots();
	$new = array();
	foreach ($trusted_roots as $root) {
		if (md5($root) != $md5) {
			$new[] = $root;
		}
	}
	update_option('openidserver_trusted_roots', $new);
}

function openidserver_get_trusted_roots() {
	$trusted_roots = get_option('openidserver_trusted_roots');
	if (!is_array($trusted_roots)) {
		$trusted_roots = array();
	}
	return $trusted_roots;
}

function openidserver_get_server_url() {
	return get_option('siteurl') . '/?openidserver=1';
}

function openidserver_user_is_logged_in() {
	return current_user_can('manage_options');
}

function openidserver_user_owns_identity($identity) {
	return openidserver_user_is_logged_in() &&
		openidserver_openid_for_current_site() == $identity;
}

function openidserver_server() {	
	$store = new WordPress_OpenID_OptionStore();
	$server = new Auth_OpenID_Server($store);
	
	$GLOBALS['_openidserver_server'] = $server;
	
	$method = $_SERVER['REQUEST_METHOD'];
	$request = $_REQUEST;

	$request = Auth_OpenID::fixArgs($request);
	$request = $server->decodeRequest($request);

	if (OPENIDSERVER_DEBUG_MESSAGES) {
		ob_start();
		print_r($_POST);
		$post_data = ob_get_contents();
		ob_end_clean();
		ob_start();
		print_r($request);
		$request_data = ob_get_contents();
		ob_end_clean();
		error_log('Request method: ' . $_SERVER['REQUEST_METHOD']);
		error_log('  Query string: ' . $_SERVER['QUERY_STRING']);
		error_log('  Post data: ' . $post_data);
		error_log('  Request object: ' . $request_data);
	}

	if (!$request) {
		openidserver_this_is_an_openid_server();
		exit;
	}

	if (in_array($request->mode,
			array('checkid_immediate', 'checkid_setup'))) {
		if (openidserver_user_owns_identity($request->identity) &&
			openidserver_is_trusted($request->identity, $request->trust_root)) {
			$response =& $request->answer(true);
		} else if ($request->immediate) {
			$response =& $request->answer(false, openidserver_get_server_url());
		} else {
			if (!openidserver_user_is_logged_in()) {
				openidserver_you_need_to_log_in($request);
				exit;
			} elseif (!openidserver_user_owns_identity($request->identity)) {
				openidserver_shared_header('Error');
				echo '<p>You do not own <strong>'.
					htmlspecialchars($request->identity).
					'</strong>. ';
				if (substr($request->identity, -1, 1) != '/') {
					echo 'You should try again with a trailing slash.';
				}
				echo '</p>';
				openidserver_shared_footer();
				exit;
			} else {
				// This function inspects $_GET to check for sreg requests
				return openidserver_decide_page($request);
				exit;
			}
		}
	} else {
		$response =& $server->handleRequest($request);
	}
	// If there is an openidserver_pending cookie, we should delete it here
	global $current_site;
	$domain = $current_site->domain;
	setcookie(
		'openidserver_pending', '', time() - 24 * 60 * 60, '/', '.'.$domain
	);
	
	openidserver_send_openid_response($response);
	exit;
}

function openidserver_send_openid_response($response) {
	$server = $GLOBALS['_openidserver_server'];
	$webresponse =& $server->encodeResponse($response);

	if (OPENIDSERVER_DEBUG_MESSAGES) {
		error_log('$server->encodeResponse($response):');
		ob_start();
		print_r($webresponse);
		$post_data = ob_get_contents();
		ob_end_clean();
		error_log($post_data);
	}
	
	foreach ($webresponse->headers as $key => $value) {
		header("$key: $value");
	}
	print $webresponse->body;
	exit;
}

function openidserver_decide_page($request) {
	/* The decide form posts back to itself, preserving the GET arguments
	   exactly. This means we can examine $_POST here to see if the user
	   has made their decision.
	*/
	global $current_blog;
	$secret = get_option('secret');
	$action = $_SERVER['REQUEST_URI'];
	// nonce provides CSRF protection; if nonce check fails, form is redisplayed
	$nonce = md5($secret . $action . $request->trust_root);
	if ($_POST && $nonce == $_POST['openidserver_nonce']) {
		if (isset($_POST['openidserver_always'])) {
			// Add to our trust roots
			openidserver_add_trust_root($request->trust_root);
		}
		if (isset($_POST['openidserver_always']) ||
			isset($_POST['openidserver_once'])) {
			// Send back a positive response, adding sreg data if required
			$response =& $request->answer(true);
			/*
			if (isset($_POST['openidserver_send_sreg']) &&
				isset($_POST['openidserver_sreg'])) {
				foreach ($_POST['openidserver_sreg'] as $key => $value) {
					$response->addField('sreg', $key, $value);
				}
			}
			*/
			openidserver_send_openid_response($response);
			exit;
		} elseif (isset($_POST['openidserver_always'])) {
			openidserver_add_trust_root($request->trust_root);
			openidserver_send_openid_response($request->answer(true));
			exit;
		} else { /* Cancel button */
			openidserver_send_openid_response($request->answer(false));
			exit;
		}
		exit;
	}
	
	$identity = $request->identity;
	$trust_root = $request->trust_root;
	
	// If we've been asked for sreg data, build that part of the form first
	$sreg_form_fields = openidserver_construct_sreg_form_fields();
	
	openidserver_shared_header('Trust this site with your identity?');
	?>
	<h2>Trust this site with your identity?</h2>
	<form action="<?php echo htmlspecialchars($action); ?>" method="POST">
	<?php echo $sreg_form_fields; ?>
	<p>Do you want to pass your <strong><?php echo htmlspecialchars($identity); ?></strong> identity to <strong><?php echo htmlspecialchars($trust_root); ?></strong>?</p>
	<p><input type="submit" name="openidserver_cancel" value="No">
	<input type="submit" name="openidserver_once" value="Yes; just this time">
	<input type="submit" name="openidserver_always" value="Yes; always">
	<input type="hidden" name="openidserver_nonce" value="<?php echo htmlspecialchars($nonce); ?>"></p>
	</form>
	<?php
	openidserver_shared_footer();
	exit;
}

function openidserver_construct_sreg_form_fields() {
	/*
	If the query string includes openid_sreg_required or openid_sreg_optional,
	the relying party has asked for additional information from us. We'll 
	provide extra form fields for these, prepopulated with data from our user's
	profile. We treat optional and required fields the same at the moment.
	*/
	global $current_user;
	if (!isset($_GET['openid_sreg_required']) && 
		!isset($_GET['openid_sreg_optional'])) {
		if (OPENIDSERVER_DEBUG_MESSAGES) {
			error_log('No sreg request, so no extra fields needed');
		}
		return ''; // No sreg request, so no extra fields needed
	}
	if (OPENIDSERVER_DEBUG_MESSAGES) {
		error_log('sreg request!');
	}
	$requested_keys = explode(',', 
		(isset($_GET['openid_sreg_required']) ?
			$_GET['openid_sreg_required'] : '') . 
		(isset($_GET['openid_sreg_optional']) ?
			$_GET['openid_sreg_optional'] : '')
	);
	$requested_keys = array_filter(array_map('trim', $requested_keys));
	$known_data = array(
		'email' => htmlspecialchars($current_user->user_email),
		'nickname' => htmlspecialchars($current_user->nickname),
		'fullname' => htmlspecialchars(
			$current_user->first_name.' '.$current_user->last_name
		),
	/* We don't yet provide data for:
		'dob' => '',
		'gender' => '', # M or F
		'postcode' => '',
		'country' => '',
		'language' => '',
		'timezone' => ''
	*/
	);
	$human_readable_names = array(
		// These must correspond to the keys in $known_data
		'email' => 'e-mail address',
		'nickname' => 'nickname',
		'fullname' => 'full name',
	);
	$form = '';
	
	foreach ($requested_keys as $key) {
		if (isset($known_data[$key])) {
			$form .= <<<EOD
<p><label for="openidserver_sreg_{$key}">Your {$human_readable_names[$key]}:
<br />
<input type="text" name="openidserver_sreg[{$key}]"
    id="openidserver_sreg_{$key}" value="{$known_data[$key]}" /></label></p>
EOD;
		}
	}
	if ($form) {
		// Add the explanatory text
		$form = '<p>The site has requested the following information be '.
		'passed to it. You can edit the information before it is sent if you '.
		'like.</p>'.
		'<fieldset><legend>Requested profile information</legend>'.
		$form .
		'<label><input type="checkbox" checked="checked"'.
		'  name="openidserver_send_sreg" id="openidserver_send_sreg" /> '.
		'Send this information to the site</label>'.
		'</fieldset><br style="clear: both">'.
		'<script type="text/javascript">'.
		'window.onload = function() {
			var check = document.getElementById("openidserver_send_sreg");
			var inputs = document.getElementsByTagName("input");
			function onchange() {
				var disabled = !check.checked;
				for (var input, i = 0; input = inputs[i]; i++) {
					if (input.type != "text") {
						continue;
					}
					input.disabled = disabled;
					input.style.color = disabled ? "#ccc" : "#000";
				}
			}
			onchange();
			check.onchange = onchange;
			check.onclick = onchange; // For IE
		}'.
		'</script>';
	}
	return $form;
}

function openidserver_this_is_an_openid_server() {
	echo "This is an OpenID server";
	if (OPENIDSERVER_DEBUG_MESSAGES && openidserver_user_is_logged_in()) {
		echo "... and you are logged in!";
	}
	exit;
}

function openidserver_admin() {
	// Admin panel interface for managing OpenID
	$openid = openidserver_openid_for_current_site();
	
	if ($_POST) {
		check_admin_referer('openidserver');
		/*  _POST keys of format del_1c6380fe94657de8997d6ac678bffe2b are 
			md5() hashes of URLs that should be removed from $trusted_roots
			If new_root and add are set, add new_root to $trusted_roots
		*/
		if (isset($_POST['add']) && isset($_POST['new_root'])) {
			openidserver_add_trust_root($_POST['new_root']);
		}
		foreach (array_keys($_POST) as $key) {
			if (substr($key, 0, 4) == 'del_') {
				openidserver_remove_trust_root_by_md5(substr($key, 4));
			}
		}
	}
	$trusted_roots = openidserver_get_trusted_roots();
	?>
	<div class="wrap">
	<h2>Manage your OpenID</h2>
	<p>OpenID allows you to log in to other sites that support the
		OpenID standard.</p>
	<p>Your OpenID is <strong><?php echo htmlspecialchars($openid); ?></strong></p>
	<h3>Your trusted sites</h3>
	<p>If a site is on your trusted sites list, you will not be asked if you trust that site when you attempt to log in to it.</p>
	<form id="openidserverform" action="" method="post">
	<?php wp_nonce_field('openidserver'); echo "\n"; ?>
	<table class="widefat">
		<thead>
		<tr>
		<th scope="col">URL</th>
		<th scope="col"></th>
		</tr>
		</thead>
		<tbody>
		<tr class="<?php $cnt = 0; echo ($cnt++ % 2) ? '': 'alternate'; ?>">
			<td><input type="text" name="new_root" style="width: 95%" /></td>
			<td><input type="submit" 
				name="add" 
				value="Add to list" /></td>
		</tr>
		<?php foreach ($trusted_roots as $root): ?>
		<tr class="<?php echo ($cnt++ % 2) ? '': 'alternate'; ?>">
			<td><?php echo htmlspecialchars($root); ?></td>
			<td><input type="submit" 
				name="del_<?php echo md5($root); ?>" 
				value="Remove from list" /></td>
		</tr>
		<?php endforeach; ?>
		</tbody>
	</table>
	</form>
	</div>
	<?php
}

function openidserver_you_need_to_log_in($request) {
	// $request is the OpenID request; we stash it in wp_options so we can 
	// redisplay it to them later if necessary. We only stash one at a time.
	global $current_site;
	openidserver_store_pending_request($request);
	
	openidserver_shared_header('You need to sign in');
?>
<h2>You need to sign in</h2>
<p>You need to sign in to <strong><?php echo $current_site->domain ?></strong> to complete this process.</p>
<p>You should <strong>use a bookmark</strong> or <strong>type in the address</strong> to do this. This page does not contain any links, to protect you from phishing.</p>
<?php
	openidserver_shared_footer();
	exit;
}

function openidserver_shared_header($title) {
	global $current_site;
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title><?php echo htmlspecialchars($title); ?></title>
<link rel="stylesheet" href="<?php echo get_option('siteurl'); ?>/wp-admin/wp-admin.css" type="text/css" />
<style type="text/css">
fieldset {
  border:1px solid #CCCCCC;
  float:left;
  margin:1em 1em 1em 0pt;
  padding:0.5em 2em 1em;
  width:40%;
}
legend {
  font-family:Georgia,"Times New Roman",Times,serif;
  font-size:22px;
  padding:0.1em 0.3em;
}
</style>
</head>
<body>
<div id="wphead">
<h1><?php echo $current_site->domain; ?></h1>
</div>
<div class="wrap">
<?php
}

function openidserver_shared_footer() {
	echo "</div>\n</body>\n</html>";
}

function openidserver_store_pending_request($request) {
	/* Pending requests are stored in a browser session cookie:
	   $ts|urlencode($site_url)|urlencode($continue_url)|urlencode($trust_root)
	*/
	global $current_site;
	$timestamp = time();
	$site_url = urlencode(get_option('siteurl'));
	$continue_url = urlencode(
		get_option('siteurl') . '/?' . $_SERVER['QUERY_STRING']
	);
	$trust_root = urlencode($request->trust_root);
	$cookie_value = "$timestamp|$site_url|$continue_url|$trust_root";
	$domain = $current_site->domain;
	setcookie('openidserver_pending', $cookie_value, 0, '/', '.'.$domain);
}

function openidserver_has_pending_request() {
	/* Checks for existence of pending request without deleting it */
	if (isset($_COOKIE['openidserver_pending'])) {
		# Check signature
		$bits = explode('|', $_COOKIE['openidserver_pending'], 4);
		if (count($bits) == 4) {
			// Check cookie timestamp is less than 5 minutes old
			$timestamp = (int)$bits[0];
			if ((time() - $timestamp) < 5 * 60) {
				return true;
			} else {
				/* Delete the cookie, if possible */
				if (!headers_sent()) {
					setcookie(
						'openidserver_pending', '', time() - 24 * 60 * 60, '/',
						'.'.$domain
					);
					return false;
				}
			}
		}
	}
	return false;
}

function openidserver_get_pending_request() {
	/* This function returns any pending request. */
	global $current_site;
	$return = false;
	if (isset($_COOKIE['openidserver_pending'])) {
		$bits = explode('|', $_COOKIE['openidserver_pending'], 4);
		if (count($bits) == 4) {
			$timestamp = (int)$bits[0];
			$site_url = $bits[1];
			$continue_url = $bits[2];
			$trust_root = $bits[3];
			// Check cookie hasn't expired
			if ((time() - $timestamp) < 5 * 60) {
				$return = array(
					'site_url' => urldecode($site_url),
					'continue_url' => urldecode($continue_url),
					'trust_root' => urldecode($trust_root)
				);
			} else {
				/* Delete the cookie, if possible */
				if (!headers_sent()) {
					setcookie(
						'openidserver_pending', '', time() - 24 * 60 * 60, '/',
						'.'.$domain
					);
				}
			}
		}
	}
	return $return;
}

if (openidserver_is_enabled()) {
	class WordPress_OpenID_OptionStore extends Auth_OpenID_OpenIDStore {
		var $KEY_LEN = 20;
		var $MAX_NONCE_AGE = 21600; // 6 * 60 * 60
		function WordPress_OpenID_SerializedStore() {
			;
		}
		function getAuthKey() {
			$auth_key = get_option('openidserver_authkey');
			if (!$auth_key) {
				$auth_key = Auth_OpenID_CryptUtil::randomString($this->KEY_LEN);
				update_option('openidserver_authkey', $auth_key);
			}
			return $auth_key;
		}
		function storeAssociation($server_url, $association) {
			$key = $this->_getAssociationKey($server_url, $association->handle);
			$association_s = $association->serialize();
			$associations = get_option('openidserver_associations');
			if (!$associations) {
				$associations = array();
			}
			$associations[$key] = $association_s;
			update_option('openidserver_associations', $associations);
		}
		function getAssociation($server_url, $handle = null) {
			if ($handle === null) {
				$handle = '';
			}
			$key = $this->_getAssociationKey($server_url, $handle);
			$associations = get_option('openidserver_associations');
			if ($handle) {
				return Auth_OpenID_Association::deserialize(
					'Auth_OpenID_Association', $associations[$key]
				);
			} else {
				// Return the most recently issued association
				$matching_keys = array();
				foreach (array_keys($associations) as $assoc_key) {
					if (strpos($assoc_key, $key) === 0) {
						$matching_keys[] = $assoc_key;
					}
				}
				$matching_associations = array();
				// sort by time issued
				foreach ($matching_keys as $assoc_key) {
					$association = Auth_OpenID_Association::deserialize(
						'Auth_OpenID_Association', $associations[$assoc_key]
					);
					if ($association !== null) {
						$matching_associations[] = array(
							$association->issued, $association
						);
					}
				}
				$issued = array();
				$assocs = array();
				foreach ($matching_associations as $assoc_key => $assoc) {
					$issued[$assoc_key] = $assoc[0];
					$assocs[$assoc_key] = $assoc[1];
				}
				array_multisort($issued, SORT_DESC, $assocs, SORT_DESC,
								$matching_associations);

				// return the most recently issued one.
				if ($matching_associations) {
					list($issued, $assoc) = $matching_associations[0];
					return $assoc;
				} else {
					return null;
				}
			}
		}
		function _getAssociationKey($server_url, $handle) {
			if (strpos($server_url, '://') === false) {
				trigger_error(sprintf("Bad server URL: %s", $server_url),
							  E_USER_WARNING);
				return null;
			}
			list($proto, $rest) = explode('://', $server_url, 2);
			$parts = explode('/', $rest);
			$domain = Auth_OpenID_FileStore::_filenameEscape($parts[0]);
			$url_hash = Auth_OpenID_FileStore::_safe64($server_url);
			if ($handle) {
				$handle_hash = Auth_OpenID_FileStore::_safe64($handle);
			} else {
				$handle_hash = '';
			}
			return sprintf('%s-%s-%s-%s',
				$proto, $domain, $url_hash, $handle_hash);
		}
	
		function removeAssociation($server_url, $handle) {
			// Remove the matching association if it's found, and
			// returns whether the association was removed or not.
			$key = $this->_getAssociationKey($server_url, $handle);
			$assoc = $this->getAssociation($server_url, $handle);
			if ($assoc === null) {
				return false;
			} else {
				$associations = get_option('openidserver_associations');
				if (isset($associations[$key])) {
					unset($associations[$key]);
					update_option('openidserver_associations', $associations);
					return true;
				} else {
					return false;
				}
			}		
		}
		function storeNonce($nonce) {
			$nonces = get_option('openidserver_nonces');
			if (!$nonces) {
				$nonces = array();
			}
			$nonces[$nonce] = time();
			update_option('openidserver_nonces', $nonces);
		}
		function useNonce($nonce) {
			$nonces = get_option('openidserver_nonces');
			if (!isset($nonces[$nonce])) {
				return false;
			}
			$nonce_age = $nonces[$nonce] - time();
			unset($nonces[$nonce]);
			update_option('openidserver_nonces', $nonces);
			return $nonce_age <= $this->MAX_NONCE_AGE;
		}
		function isDumb() {
			return false;
		}
	}
}

?>
