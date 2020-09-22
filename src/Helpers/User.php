<?php

// TODO: Frage, haben wir nicht definiert, dass der Packgename auch teil des Namespaces sein soll?
namespace Helpers;

use Concrete\Core\Support\Facade\Application as App;
use Concrete\Core\User\Login\LoginService;
use Concrete\Core\User\Exception\FailedLoginThresholdExceededException;
use Concrete\Core\User\Exception\UserDeactivatedException;
use Concrete\Core\User\Exception\UserException;
use Concrete\Core\User\Exception\UserPasswordResetException;
use Concrete\Core\User\Exception\InvalidCredentialsException;
use Concrete\Core\Error\UserMessageException;
use Concrete\Core\Localization\Localization;
use Concrete\Core\Http\Request as ConcreteRequest;
use Concrete\Core\Permission\IPService;
use Concrete\Core\User\User as C5User;
use Concrete\Core\User\UserInfo;
use Concrete\Core\Validator\String\EmailValidator;
use Concrete\Core\User\ValidationHash;
use Concrete\Core\Support\Facade\Config;
use Concrete\Core\Support\Facade\Application as Core;
use Concrete\Core\Support\Facade\Session;
use Concrete\Core\Support\Facade\Database;
use Concrete\Core\Permission\Checker as Permissions;
use Concrete\Core\Support\Facade\Log;
use PermissionKey;

class User
{
    public function create($email, $password, $username = null)
    {
        $error = App::make('helper/validation/error');

        try {
            if ($username) {
                $username = trim($username);
                $username = preg_replace('/ +/', ' ', $username);
                $this->app->make('validator/user/name')->isValid($username, $error);
            } else {
                $userService = $this->app->make(\Concrete\Core\Application\Service\User::class);
                $username = $userService->generateUsernameFromEmail($username);
            }

            $this->app->make('validator/user/email')->isValid($email, $error);
            $this->app->make('validator/password')->isValid($password, $error);

            if (!$error->has()) {
                \Core::make('user/registration')->create(['uName' => $username, 'uEmail' => $email, 'uPassword' => $password]);
                return true;
            }

        } catch (\Exception $e) {
            $error = App::make('helper/validation/error');
            $error->add($e);
        }

        if ($error->has()) {
            return ['error' => $error->getList()];
        }
    }

    public function sendValidationEmail($uID)
    {
        // if ($this->canActivateUser && $this->app->make('helper/validation/token')->validate()) {
        //     $this->app->make('user/status')->sendEmailValidation($this->user);
        //     $this->redirect('/dashboard/users/search', 'view', $this->user->getUserID(), 'email_validation_sent');
        // }
    }
}
