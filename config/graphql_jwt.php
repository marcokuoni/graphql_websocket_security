<?php

return [
    'auth_secret_key' => getenv('GRAPHQL_JWT_AUTH_SECRET_KEY'),
    'auth_refresh_secret_key' => getenv('GRAPHQL_JWT_AUTH_REFRESH_SECRET_KEY'),
    'auth_expire' => 30,
    'auth_refresh_expire' => 7200,
    'cookie' => [
        'cookie_name' => 'mainApp',
        'cookie_path' => DIR_REL . '/', //Path who can change the cookie
        'cookie_lifetime' => 7200,  //cookie lifetime
        'cookie_domain' => false,   //domain who can change the cookie
        'cookie_secure' => false,   //Just https is accepted
        'cookie_httponly' => true,  //no client can read the cookie
    ]
];
