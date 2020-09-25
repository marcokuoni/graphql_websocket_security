<?php

// TODO: Frage, haben wir nicht definiert, dass der Packgename auch teil des Namespaces sein soll?
namespace Helpers;

use Concrete\Core\Support\Facade\Application as App;

class User
{
    public function create($email, $password, $username = null)
    {
        $error = App::make('helper/validation/error');
        $result = [
            'result' => null,
            'errors' => []
        ];

        try {
            App::make('validator/user/email')->isValid($email, $error);
            App::make('validator/password')->isValid($password, $error);

            if ($username) {
                $username = trim($username);
                $username = preg_replace('/ +/', ' ', $username);
                App::make('validator/user/name')->isValid($username, $error);
            } else {
                $userService = App::make(\Concrete\Core\Application\Service\User::class);
                $username = $userService->generateUsernameFromEmail($email);
            }

            if (!$error->has()) {
                $newUser = \Core::make('user/registration')->create(['uName' => $username, 'uEmail' => $email, 'uPassword' => $password]);
                $result['result'] = ['email' => $newUser->getUserEmail(), 'userName' => $newUser->getUserName() ];
                if ($newUser->error !== ''){
                    $result['errors'][] = $newUser->error;
                }
                return $result;
            }
        } catch (\Exception $e) {
            $error->add($e);
        }

        if ($error->has()) {
            foreach ($error->getList() as $value) {
                $result['errors'][] = $value->getMessage();
            }
            return $result;
        }
    }

    public function sendValidationEmail($uID)
    {
        // if ($this->canActivateUser && App::make('helper/validation/token')->validate()) {
        //     App::make('user/status')->sendEmailValidation($this->user);
        //     $this->redirect('/dashboard/users/search', 'view', $this->user->getUserID(), 'email_validation_sent');
        // }
    }
}
