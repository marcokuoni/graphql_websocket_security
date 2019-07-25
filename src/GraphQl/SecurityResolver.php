<?php

namespace GraphQl;

use Concrete\Core\Support\Facade\Application as App;
use Concrete\Core\User\User;
use Exception;

class SecurityResolver
{
    public static function get()
    {
        $queryType = [
            'me' => function ($root, $args) {
                $auth = App::make(\Helpers\Auth::class);
                $user = $auth->authenticated();

                if (empty($user)) {
                    throw new \Exception(t('The JWT token could not be returned'));
                }

                return json_decode(json_encode($user));
            },
            'jwtAuthToken' => function ($root, $args) {
                $auth = App::make(\Helpers\Auth::class);
                $user = $auth->authenticated();
                $token = $auth->getToken($user);

                if (empty($token)) {
                    throw new \Exception(t('The JWT token could not be returned'));
                }

                return !empty($token) ? $token : null;
            },
            'jwtRefreshToken' => function ($root, $args) {
                $auth = App::make(\Helpers\Auth::class);
                $user = $auth->authenticated();
                $token = $auth->getRefreshToken($user);

                if (empty($token)) {
                    throw new \Exception(t('The JWT token could not be returned'));
                }

                return !empty($token) ? $token : null;
            },
            'jwtUserSecret' => function ($root, $args) {
                $auth = App::make(\Helpers\Auth::class);
                $user = $auth->authenticated();
                $secret = $auth->getUserJwtSecret($user);

                if (empty($secret)) {
                    throw new \Exception(t('The user secret could not be returned'));
                }

                return !empty($secret) ? $secret : null;
            },
            'jwtAuthExpiration' => function ($root, $args) {
                $auth = App::make(\Helpers\Auth::class);
                $expiration = $auth->getTokenExpiration();

                return !empty($expiration) ? $expiration : null;
            },
            'isJwtAuthSecretRevoked' => function ($root, $args) {
                $auth = App::make(\Helpers\Auth::class);
                $user = $auth->authenticated();
                $revoked = $auth->isJwtSecretRevoked($user);

                return true == $revoked ? true : false;
            },

        ];

        $mutationType = [
            'login' => function ($root, $args) {
                $username = (string) $args['username'];
                $password = (string) $args['password'];

                $auth = App::make(\Helpers\Auth::class);
                return $auth->loginAndGetToken($username, $password);
            },
            'refreshJwtAuthToken' => function ($root, $args) {
                $refreshToken = (string) $args['jwtRefreshToken'];

                $auth = App::make(\Helpers\Auth::class);
                $refreshToken = !empty($refreshToken) ? $auth->validateToken($refreshToken) : null;

                $id = isset($refreshToken->data->user->uID) || 0 === $refreshToken->data->user->uID ?
                    (int) $refreshToken->data->user->uID : 0;
                if (empty($id)) {
                    throw new \Exception(t('The provided refresh token is invalid'));
                }

                $user = User::getByUserID($id);
                $authToken = $auth->getToken($user, false);

                return [
                    'authToken' => $authToken,
                    'refreshToken' => $auth->getRefreshToken($user),
                    'user'         => json_decode(json_encode($user)),
                ];
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
