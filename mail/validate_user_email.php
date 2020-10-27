<?php

defined('C5_EXECUTE') or die("Access Denied.");

if ($validationUrl) {
    $url = $validationUrl . '/' . $uHash;
} else {
    $url = View::url('/login', 'callback', 'concrete', 'v', $uHash);
}

$subject = $site . " " . t("Registration - Validate Email Address");
$body = t("

You must click the following URL in order to activate your account for %s:

%s 

Thanks for your interest in %s

", $site, $url, $site);
