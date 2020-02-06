<?php

namespace GraphQl;

use Concrete\Core\Support\Facade\Application as App;

class SecurityResolver
{
    public static function get()
    {
        $queryType = [
            'me' => function ($root, $args) {
                $authorize = App::make(\Helpers\Authorize::class);
                $user = $authorize->authenticated();
                $returnUser = [
                    "uID" => '',
                    "uName" => '',
                ];

                if (!empty($user)) {
                    $returnUser = [
                        "uID" => $user->getUserID(),
                        "uName" => $user->getUserName(),
                    ];
                }

                return $returnUser;
            },
        ];

        $mutationType = [
            'login' => function ($root, $args) {
                $username = (string) $args['username'];
                $password = (string) $args['password'];

                $authorize = App::make(\Helpers\Authorize::class);
                return $authorize->loginAndGetToken($username, $password);
            },
            'logout' => function ($root, $args) {
                $authorize = App::make(\Helpers\Authorize::class);
                return $authorize->logout();
            },
            'refreshToken' => function ($root, $args) {
                $authorize = App::make(\Helpers\Authorize::class);
                return $authorize->refreshToken();
            },
            'forgotPassword' => function ($root, $args) {
                $username = (string) $args['username'];
                $currentLanguage = (string) $args['currentLanguage'];

                $authenticate = App::make(\Helpers\Authenticate::class);
                return $authenticate->forgotPassword($username, $currentLanguage);
            },
            'changePassword' => function ($root, $args) {
                $password = (string) $args['password'];
                $passwordConfirm = (string) $args['passwordConfirm'];
                $token = (string) $args['token'];

                $authenticate = App::make(\Helpers\Authenticate::class);
                return $authenticate->changePassword($password, $passwordConfirm, $token);
            },
        ];

        $subscriptionType = [];

        return [
            'Query'    => $queryType,
            'Mutation' => $mutationType,
            'Subscription' => $subscriptionType,
        ];
    }
}
