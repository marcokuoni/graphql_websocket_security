<?php

return [
    'just_with_valid_token' => false,
    'auth_secret_key' => getenv('GRAPHQL_JWT_AUTH_SECRET_KEY'),
    'auth_expire' => 300,
    'log_anonymus_users' => false,
    'log_requests' => false,
];
