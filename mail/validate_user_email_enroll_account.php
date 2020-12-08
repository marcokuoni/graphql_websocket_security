<?php

defined('C5_EXECUTE') or die("Access Denied.");

if ($validationUrl) {
    $url = $validationUrl . '/' . $uHash;
} else {
    $url = View::url('/login', 'callback', 'concrete', 'v', $uHash);
}

$subject = $site . " " . t("Account created for you - Validate Email Address");
$body = t("

There was an account created for you on %s.

After the activation you will have to set a new password to gain access.

In order to activate please follow this URL :

%s 

Thanks for your interest in %s

", $site, $url, $site);
