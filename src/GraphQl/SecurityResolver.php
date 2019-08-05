<?php

namespace GraphQl;

use Concrete\Core\Support\Facade\Application as App;
use Concrete\Core\User\User;
use Entity\AnonymusUser as AnonymusUserEntity;

class SecurityResolver
{
    public static function get()
    {
        $queryType = [
            'me' => function ($root, $args) {
                $authorize = App::make(\Helpers\Authorize::class);
                $user = $authorize->authenticated();

                if (empty($user)) {
                    throw new \Exception(t('The JWT token could not be returned'));
                } else {
                    $returnUser = [
                        "uID" => $user->getUserID(),
                        "uName" => $user->getUserName(),
                        "anonymous" => get_class($user) === AnonymusUserEntity::class,
                        "uGroups" => $user->getUserGroups()
                    ];
                }

                return $returnUser;//json_decode(json_encode($user));
            },
            'jwtAuthToken' => function ($root, $args) {
                $authorize = App::make(\Helpers\Authorize::class);
                $user = $authorize->authenticated();
                $token = $authorize->getToken($user);

                if (empty($token)) {
                    throw new \Exception(t('The JWT token could not be returned'));
                }

                return !empty($token) ? $token : null;
            },
            'jwtRefreshToken' => function ($root, $args) {
                $authorize = App::make(\Helpers\Authorize::class);
                $user = $authorize->authenticated();
                $token = $authorize->getRefreshToken($user);

                if (empty($token)) {
                    throw new \Exception(t('The JWT token could not be returned'));
                }

                return !empty($token) ? $token : null;
            },
            'jwtUserSecret' => function ($root, $args) {
                $authorize = App::make(\Helpers\Authorize::class);
                $user = $authorize->authenticated();
                $secret = $authorize->getUserJwtSecret($user);

                if (empty($secret)) {
                    throw new \Exception(t('The user secret could not be returned'));
                }

                return !empty($secret) ? $secret : null;
            },
            'jwtAuthExpiration' => function ($root, $args) {
                $authorize = App::make(\Helpers\Authorize::class);
                $expiration = $authorize->getTokenExpiration();

                return !empty($expiration) ? $expiration : null;
            },
            'isJwtAuthSecretRevoked' => function ($root, $args) {
                $authorize = App::make(\Helpers\Authorize::class);
                $user = $authorize->authenticated();
                $revoked = $authorize->isJwtSecretRevoked($user);

                return true == $revoked ? true : false;
            },

        ];

        $mutationType = [
            'login' => function ($root, $args) {
                $username = (string) $args['username'];
                $password = (string) $args['password'];

                $authorize = App::make(\Helpers\Authorize::class);
                return $authorize->loginAndGetToken($username, $password);
            },
            'loginAnonymous' => function ($root, $args) {
                $authorize = App::make(\Helpers\Authorize::class);
                return $authorize->loginAndGetTokenFromAnonymus();
            },
            'logout' => function ($root, $args) {
                $authorize = App::make(\Helpers\Authorize::class);
                return $authorize->logout();
            },
            'refreshJwtAuthToken' => function ($root, $args) {
                $refreshToken = (string) $args['jwtRefreshToken'];

                $authorize = App::make(\Helpers\Authorize::class);
                $refreshToken = !empty($refreshToken) ? $authorize->validateToken($refreshToken) : null;

                $id = isset($refreshToken->data->user->uID) ? $refreshToken->data->user->uID : 0;
                if (empty($id)) {
                    throw new \Exception(t('The provided refresh token is invalid'));
                }

                if ($refreshToken->data->user->anonymus) {
                    $anonymusUser = App::make(\Helpers\AnonymusUser::class);
                    $user =  $anonymusUser->getAnonymusUser($id);
                } else {
                    $user = User::getByUserID($id);
                }

                $authToken = $authorize->getToken($user, false);

                return [
                    'authToken' => $authToken,
                    'refreshToken' => $authorize->getRefreshToken($user),
                    'user'         => json_decode(json_encode($user)),
                ];
            },
            'revokeJwtUserSecret' => function ($root, $args) {
                $revoke = (bool) $args['revoke'];

                $authorize = App::make(\Helpers\Authorize::class);
                $user = $authorize->authenticated();

                if ($revoke) {
                    return $authorize->revokeUserSecret($user);
                } else {
                    return $authorize->unrevokeUserSecret($user);
                }
            },
            'refreshJwtUserSecret' => function ($root, $args) {
                $authorize = App::make(\Helpers\Authorize::class);
                $user = $authorize->authenticated();

                return $authorize->issueNewUserSecret($user) !== null ? true : false;
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
