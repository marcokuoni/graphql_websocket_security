<?php

namespace GraphQl;

use Concrete\Core\Support\Facade\Application as App;
use Config;
use Concrete5GraphqlWebsocket\Helpers\HasAccess;

class UserResolver
{
    public static function get()
    {
        $queryType = [];

        $mutationType = [
            'createUser' => function ($root, $args, $context) {

                $error = App::make('helper/validation/error');

                try {
                    if (Config::get('concrete.user.registration.enabled') || HasAccess::checkByGroup($context, ['admin'])) {

                        $username = (string) $args['username'];
                        $email = (string) $args['email'];
                        $password = (string) $args['password'];

                        $user = App::make(\Helpers\User::class);
                        if ($user->create($username, $email, $password)) {
                            // $authorize = App::make(\Helpers\Authorize::class);
                            // return $authorize->loginAndGetToken($username, $password);
                            return ['username' => $username, 'email' => $email];
                        } else {
                            return ['error' => 'Beim Erstellen des Benutzers ist ein Fehler aufgetreten'];
                        }
                    };
                } catch (\Exception $e) {
                    $error->add($e);
                }

                if ($error->has()) {
                    return ['error' => $error->getList()];
                }
            },
            'sendValidationEmail' => function ($root, $args, $context) {
                // $me = $this->app->make(User::class);
                // $ui = \Core::make('Concrete\Core\User\UserInfoRepository')->getByID(
                //     $this->app->make('helper/security')->sanitizeInt($args['email'])
                // );
                // if (is_object($ui)) {
                //     $up = new Permissions($ui);
                //     if (!$up->canViewUser()) {
                //         throw new \Exception(t('Access Denied.'));
                //     }
                //     $tp = new Permissions();
                //     $pke = PermissionKey::getByHandle('edit_user_properties');
                //     $this->user = $ui;
                //     $this->assignment = $pke->getMyAssignment();
                //     $this->canEdit = $up->canEditUser();
                //     $this->canActivateUser = $this->canEdit && $tp->canActivateUser() && $me->getUserID() != $ui->getUserID();
                // }
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
