<?php

return [
    'just_with_valid_token' => true,
    'auth_secret_key' => getenv('GRAPHQL_JWT_AUTH_SECRET_KEY'),
    'auth_refresh_secret_key' => getenv('GRAPHQL_JWT_AUTH_REFRESH_SECRET_KEY'),
    'auth_expire' => 30,
    'auth_refresh_expire' => 86400 * 365,
    'log_requests' => false,
    'one_time_auto_refresh' => true,
    'cookie' => [
        'cookie_name' => 'mainApp',
        'cookie_path' => DIR_REL . '/', //Path who can change the cookie
        'cookie_lifetime' => 86400 * 365,  //cookie lifetime
        'cookie_domain' => false,   //domain who can change the cookie
        'cookie_secure' => false,   //Just https is accepted
        'cookie_httponly' => true,  //no client can read the cookie
    ],
    'anonymus_secret' => '',
    'anonymus_refresh_count' => 0,
    'anonymus_revoked' => false,
    'anonymus_token_expires' => 0,
    'anonymus_refresh_token_expires' => 0,
    'anonymus_get_not_before' => 0,
    'anonymus_last_request' => 0,
    'anonymus_last_request_ip' => '',
    'anonymus_last_request_agent' => '',
    'anonymus_last_request_timezone' => '',
    'anonymus_last_request_language' => '',
    'anonymus_request_count' => 0
];
