<?php

namespace GraphQl;

use Concrete\Core\Support\Facade\Application as App;

use C5GraphQl\UserManagement\UserResolverHandler;

class UserManagementResolver
{
    public static function get()
    {
        $queryType = [
            'getDisplayName' => function ($root, $args, $context) {
                $urh = App::make(UserResolverHandler::class);
                return $urh->getDisplayName($root, $args, $context);
            },
            'getDisplayNameById' => function ($root, $args, $context) {
                $urh = App::make(UserResolverHandler::class);
                return $urh->getDisplayName($root, $args, $context);
            },
            'getUser' => function ($root, $args, $context) {
                $urh = App::make(UserResolverHandler::class);
                return $urh->getUser($root, $args, $context);
            },
            'getUserById' => function ($root, $args, $context) {
                $urh = App::make(UserResolverHandler::class);
                return $urh->getUser($root, $args, $context);
            },
            'getUsers' => function ($root, $args, $context) {
                $urh = App::make(UserResolverHandler::class);
                return $urh->getUsers($root, $args, $context);
            },
        ];

        $mutationType = [
            'createUser' => function ($root, $args, $context) {
                $urh = App::make(UserResolverHandler::class);
                return $urh->createUser($root, $args, $context);
            },
            'updateUser' => function ($root, $args, $context) {
                $urh = App::make(UserResolverHandler::class);
                return $urh->updateUser($root, $args, $context);
            },
            'updateUserById' => function ($root, $args, $context) {
                $urh = App::make(UserResolverHandler::class);
                return $urh->updateUser($root, $args, $context);
            },
            'sendValidationEmail' => function ($root, $args, $context) {
                $urh = App::make(UserResolverHandler::class);
                return $urh->sendValidationEmail($root, $args, $context);
            },
            'sendValidationEmailById' => function ($root, $args, $context) {
                $urh = App::make(UserResolverHandler::class);
                return $urh->sendValidationEmail($root, $args, $context);
            },
            'validateEmail' => function ($root, $args, $context) {
                $urh = App::make(UserResolverHandler::class);
                return $urh->validateEmail($root, $args, $context);
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
