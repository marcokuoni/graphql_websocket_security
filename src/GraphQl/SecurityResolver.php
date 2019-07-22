<?php
namespace GraphQl;

use Concrete\Core\Support\Facade\Application as App;

class SecurityResolver
{
    public static function get()
    {
        $queryType = [
            'getUser' => function ($root, $args) {
                $id = (int)$args['id'];

                return json_decode(json_encode(null));
            }
        ];

        $mutationType = [
            'login' => function ($root, $args) {
                $username = (string)$args['username'];
                $password = (string)$args['password'];

                $auth = App::make(\Helpers\Auth::class);
                return $auth->loginAndGetToken($username, $password);
            },
            'refreshJwtAuthToken' => function ($root, $args) {
                $refreshToken = (string)$args['jwtRefreshToken'];

                return json_decode(json_encode(['authToken' => 'test']));
            }
        ];

        $subscriptionType = [];

        return [
            'Query'    => $queryType,
            'Mutation' => $mutationType,
            'Subscription' => $subscriptionType,
        ];
    }
}
