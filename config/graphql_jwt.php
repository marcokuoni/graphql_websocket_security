<?php

return [
    'auth_secret_key' => getenv('GRAPHQL_JWT_AUTH_SECRET_KEY'),
    'auth_refresh_secret_key' => getenv('GRAPHQL_JWT_AUTH_REFRESH_SECRET_KEY'),
    'auth_expire' => 30, //[s] auth token lifetime
    'auth_refresh_expire' => 7200, //[s] refresh token lifetime
    'cookie' => [
        'cookie_name' => '1dW4ed4cDe4dfdw45',         //cookie name, radom recommended
        'cookie_path' => '/refresh_token', //Indicates the path that must exist in the requested URL for the browser to send the Cookie header
        'cookie_lifetime' => 7200,  //[s] cookie lifetime
        'cookie_domain' => '',   //Defines the host to which the cookie will be sent
        'cookie_secure' => true,   //Just https is accepted
        'cookie_httponly' => true,  //no client can read the cookie
        'cookie_same_site' => 'Strict',  //declare if your cookie should be restricted to a first-party or same-site context
        'cookie_raw' => true  // the cookie is html encoded
    ],
    'adminArray' => [
        '/Administrators'
    ],
    'appManagerArray' => [
        '/Administrators'
    ],
];
