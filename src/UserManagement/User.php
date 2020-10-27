<?php

namespace C5GraphQl\UserManagement;

use Concrete\Core\Support\Facade\Application as App;
use Concrete\Core\Support\Facade\Config;

use C5GraphQl\User\StatusService;

class User
{
    public function create($email, $password, $username = null, $validationUrl = null)
    {
        $validationErrors = App::make('helper/validation/error');

        $result = [
            'result' => null,
            'isNewUser' => true,
            'validationErrors' => []
        ];

        try {
            App::make('validator/user/email')->isValid($email, $validationErrors);
            App::make('validator/password')->isValid($password, $validationErrors);

            if ($username) {
                $username = trim($username);
                $username = preg_replace('/ +/', ' ', $username);
                App::make('validator/user/name')->isValid($username, $validationErrors);
            } else {
                $userService = App::make(\Concrete\Core\Application\Service\User::class);
                $username = $userService->generateUsernameFromEmail($email);
            }

            if (!$validationErrors->has()) {
                $data = [
                    'uName' => $username,
                    'uEmail' => $email,
                    'uPassword' => $password
                ];
                //creates a user with uIsValidated = 0 if email validation is on
                $newUser = App::make('user/registration')->createFromPublicRegistration($data);

                //send validation email
                if (Config::get('concrete.user.registration.validate_email')) {
                    App::make(StatusService::class)->sendEmailValidation($newUser, $validationUrl);
                }
                $result['result'] = ['uEmail' => $newUser->getUserEmail(), 'uName' => $newUser->getUserName()];
                return $result;
            } else {
                foreach ($validationErrors->getList() as $value) {
                    $result['validationErrors'][] = $value->getMessage();
                    return $result;
                }
            }
        } catch (\Exception $e) {
            throw $e;
        }
    }
}
