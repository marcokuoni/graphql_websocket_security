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
                        $result = $user->create($email, $password, $username);
                        return json_decode(json_encode($result));
                    };
                } catch (\Exception $e) {
                    $error->add($e);
                }

                if ($error->has()) {
                    $result = [
                        'result' => null,
                        'errors' => []
                    ];
                    foreach ($error->getList() as $value) {
                        $result['errors'][] = $value->getMessage();
                    }
                    return $result;
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
            'User' => $userType,
            'Query'    => $queryType,
            'Mutation' => $mutationType,
            'Subscription' => $subscriptionType,
        ];
    }
}
