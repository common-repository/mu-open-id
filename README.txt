=== OpenID Provider for WordPress MU ===
Contributors: swillison
Tags: openid, wordpressmu
Requires at least: 1.1mu
Tested up to: 1.2mu
Stable tag: 0.91

Adds an OpenID provider system to WordPress MU, making every WordPress MU hosted weblog an OpenID.

== Description ==

Once installed, OpenID 1.1 link tags will be added to the homepage of every hosted weblog. Users can then use their weblog as an OpenID; when they authenticate against third party sites using that URL, WordPress MU will ask them if they wish to share their identity with the site in question. If they say yes (or click "always") they will be redirected back and logged in to that site.

The plugin also adds a new "OpenID" menu item to the Options tab in the WordPress admin application. This new page allows users to manually add and remove sites from their "always trust" list - although normally they will only modify that list indirectly by clicking the "always" button when they sign in to a site.

The plugin includes simple defence against phishing attacks. If a user tries to sign in with an OpenID but is not logged in to their WordPress MU account they will be told to navigate to the site manually or using a bookmark; presenting a log in form at that point would train users to enter their username and password at the instruction of untrusted sites.

In the above scenario, their attempted OpenID login is recorded in a cookie. When they next log in to the site (within a 5 minute window) they will be taken to the dashboard for the OpenID which they attempted to authenticate and will be presented with a link to continue that action.

== Installation ==

1. Check that your hosting provider has enabled either the `bc` or `gmp` PHP extensions. These are required for performing the big integer mathematics used in OpenID's encryption steps.
2. Upload the `php-openid/` directory and the `openidserver.php` file to your `/wp-content/mu-plugins/` directory. The plugin will activate automatically.

== Frequently Asked Questions ==

= What is OpenID and why should I care? =

Shameless self promotion: try watching [this 35 minute presentation](http://simonwillison.net/2007/openid-fowa/) or [this 7 minute screencast](http://simonwillison.net/2006/openid-screencast/).

= My users are unable to log in to another site that supports OpenID =

Older versions of the [JanRain PHP consumer library](http://www.openidenabled.com/openid/libraries/php/) are incompatible with this plugin, due to a bug in that library. You should contact the other site and ask them to ensure they are running version 1.2.2 or higher of the JanRain library.

== Screenshots ==

1. The screen asking a user if they wish to pass their identity to a third party site.
2. An extended permission screen including a request for simple registration information.
3. The landing page for unauthenticated users, illustrating the plugin's phishing protection.
