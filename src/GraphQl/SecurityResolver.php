<?php

namespace GraphQl;

use Concrete\Core\Support\Facade\Application as App;

class SecurityResolver
{
    public static function get()
    {
        $queryType = [];

        $mutationType = [
            'login' => function ($root, $args) {
                $sani = App::make('helper/security');
                $username = $sani->sanitizeString((string) $args['username']);
                $password = $sani->sanitizeString((string) $args['password']);
                $reCaptchaToken = $sani->sanitizeString((string) $args['reCaptchaToken']);

                $authorize = App::make(\Helpers\Authorize::class);
                return $authorize->loginAndGetToken($username, $password, $reCaptchaToken);
            },
            'checkNonce' => function ($root, $args) {
                $sani = App::make('helper/security');
                $username = $sani->sanitizeString((string) $args['username']);
                $nonce = $sani->sanitizeString((string) $args['nonce']);
                $u2SAPass = $sani->sanitizeString((string) $args['u2SAPass']);
                $reCaptchaToken = $sani->sanitizeString((string) $args['reCaptchaToken']);

                $authorize = App::make(\Helpers\Authorize::class);
                return $authorize->checkNonce($username, $nonce, $u2SAPass, $reCaptchaToken);
            },
            'logout' => function ($root, $args) {
                $authorize = App::make(\Helpers\Authorize::class);
                return $authorize->logout();
            },
            'forgotPassword' => function ($root, $args) {
                $sani = App::make('helper/security');
                $username = $sani->sanitizeString((string) $args['username']);
                $changePasswordUrl = $sani->sanitizeString((string) $args['changePasswordUrl']);
                $reCaptchaToken = $sani->sanitizeString((string) $args['reCaptchaToken']);

                $authenticate = App::make(\Helpers\Authenticate::class);
                return $authenticate->forgotPassword($username, $changePasswordUrl, $reCaptchaToken);
            },
            'changePassword' => function ($root, $args) {
                $sani = App::make('helper/security');
                $password = $sani->sanitizeString((string) $args['password']);
                $passwordConfirm = $sani->sanitizeString((string) $args['passwordConfirm']);
                $token = $sani->sanitizeString((string) $args['token']);
                $reCaptchaToken = $sani->sanitizeString((string) $args['reCaptchaToken']);

                $authenticate = App::make(\Helpers\Authenticate::class);
                return $authenticate->changePassword($password, $passwordConfirm, $token, $reCaptchaToken);
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
