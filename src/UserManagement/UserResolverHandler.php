<?php

namespace C5GraphQl\UserManagement;

use Concrete\Core\Support\Facade\Application as App;
use Concrete\Core\Support\Facade\Config;
use Concrete5GraphqlWebsocket\Helpers\HasAccess;
use Concrete\Core\User\UserInfoRepository;
use Concrete\Core\User\User as C5User;

use C5GraphQl\UserManagement\User;
use C5GraphQl\User\StatusService;

class UserResolverHandler
{
    public function createUser($root, $args, $context)
    {
        $sani = App::make('helper/security');
        $reCaptchaToken = $sani->sanitizeString($args['reCaptchaToken']);

        $ip_service = App::make('ip');
        if ($ip_service->isBlacklisted()) {
            throw new \Exception($ip_service->getErrorMessage());
        }

        if (!Config::get('concrete.user.registration.enabled') && !HasAccess::checkByGroup($context, ['admin'])) {
            throw new UserManagementException('not_allowed');
        }

        if (Config::get('concrete.user.registration.captcha')) {
            $captcha = App::make(\Helpers\GoogleRecaptchaCheck::class);
            if (!$captcha->check($reCaptchaToken, 'signup')) {
                throw new UserManagementException('unknown');
            }
        }

        try {
            $username = $sani->sanitizeString($args['username']);
            $email = $sani->sanitizeString($args['email']);
            $password = $sani->sanitizeString($args['password']);
            //check for existing user
            $ui = App::make('\Concrete\Core\User\UserInfoRepository')->getByEmail($email);
            $pwHasher = App::make(\Concrete\Core\Encryption\PasswordHasher::class);
            if (is_object($ui) && $pwHasher->checkPassword($password, $ui->getUserPassword())) {
                $result = [
                    'result' => ['uEmail' => $email, 'uName' => $ui->getUserName()],
                    'isNewUser' => false,
                    'validationErrors' => [],
                ];
                return json_decode(json_encode($result));
            }

            //create user
            $user = App::make(User::class);
            $validationUrl = $sani->sanitizeURL($args['validationUrl']);
            $result = $user->create($email, $password, $username, $validationUrl);
            return json_decode(json_encode($result));
        } catch (\Exception $e) {
            throw new UserManagementException('unknown');
        }
    }

    public function sendValidationEmail($root, $args, $context)
    {
        $sani = App::make('helper/security');
        $reCaptchaToken = $sani->sanitizeString($args['reCaptchaToken']);

        $ip_service = App::make('ip');
        if ($ip_service->isBlacklisted()) {
            throw new \Exception($ip_service->getErrorMessage());
        }

        $captcha = App::make(\Helpers\GoogleRecaptchaCheck::class);
        if (!$captcha->check($reCaptchaToken, 'validationEmail')) {
            throw new UserManagementException('unknown');
        }

        $uName = $sani->sanitizeString($args['uName']);
        $validationUrl = $sani->sanitizeURL($args['validationUrl']);
        $ui = App::make('Concrete\Core\User\UserInfoRepository')->getByUserName($uName);
        if (is_object($ui) && !$ui->isError()) {
            //send validation email
            App::make(StatusService::class)->sendEmailValidation($ui, $validationUrl);
            return true;
        } else {
            throw new UserManagementException('unknown');
        }
    }

    public function validateEmail($root, $args, $context) {
        $sani = App::make('helper/security');
        $token = $sani->sanitizeString($args['token']);
        $ui = $ui = App::make('\Concrete\Core\User\UserInfoRepository')->getByValidationHash($token);
        if (is_object($ui)) {
            $ui->markValidated();
            // $this->set('uEmail', $ui->getUserEmail());
            // if ($ui->triggerActivate('register_activate', USER_SUPER_ID)) {
            //     $mode = '';
            // } else {
            //     $mode = 'workflow';
            // }
            // $this->redirect('/login/callback/concrete', 'email_validated', $mode);
            return true;
        }
        return false;
    }
}
