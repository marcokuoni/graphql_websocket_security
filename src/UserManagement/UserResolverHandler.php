<?php

namespace C5GraphQl\UserManagement;

use Concrete\Core\Support\Facade\Application as App;
use Concrete\Core\Support\Facade\Config;
use Concrete5GraphqlWebsocket\Helpers\HasAccess;
use Concrete\Core\User\UserInfoRepository;
use Concrete\Core\User\User as C5User;

use C5GraphQl\UserManagement\User;
use C5GraphQl\User\StatusService;
use Concrete\Core\Support\Facade\Log;

class UserResolverHandler
{
    public function createUser($root, $args, $context)
    {
        $sani = App::make('helper/security');
        $reCaptchaToken = $sani->sanitizeString($args['reCaptchaToken']);
        $adminArray = Config::get('concrete5_graphql_websocket_security::graphql_jwt.adminArray');

        if (!is_array($adminArray)) {
            $adminArray = ['admin'];
        }

        $ip_service = App::make('ip');
        if ($ip_service->isBlacklisted()) {
            Log::addInfo('IP Blacklisted');
            throw new \Exception($ip_service->getErrorMessage());
        }

        if (!Config::get('concrete.user.registration.enabled') && !HasAccess::checkByGroup($context, $adminArray)) {
            Log::addInfo('Not allowed to create user');
            throw new UserManagementException('not_allowed');
        }

        if (Config::get('concrete.user.registration.captcha')) {
            $captcha = App::make(\Helpers\GoogleRecaptchaCheck::class);
            if (!$captcha->check($reCaptchaToken, 'signup')) {
                Log::addInfo('Captcha not valid');
                throw new UserManagementException('unknown');
            }
        }

        try {
            $username = $sani->sanitizeString($args['username']);
            $email = $sani->sanitizeString($args['email']);
            $password = $sani->sanitizeString($args['password']);
            $userLocale = $sani->sanitizeString($args['userLocale']);
            $validationUrl = $sani->sanitizeURL($args['validationUrl']);
            $groups = $args['groups'];
            //check for existing user
            $ui = App::make(UserInfoRepository::class)->getByEmail($email);
            $pwHasher = App::make(\Concrete\Core\Encryption\PasswordHasher::class);
            $user = App::make(User::class);
            if (is_object($ui) && ($pwHasher->checkPassword($password, $ui->getUserPassword()) || HasAccess::checkByGroup($context, $adminArray))) {
                $userInfo = App::make(UserInfoRepository::class)->getByName($ui->getUserName());

                if (!$userInfo) {
                    Log::addInfo('Existing user not found: ' . $username);
                    Log::addInfo('Existing user not found');
                    throw new UserManagementException('user_not_found');
                }

                $result = $user->update($userInfo, $email, $validationUrl, $userLocale, $groups);
                return json_decode(json_encode($result));
            }

            //create user
            $result = $user->create($email, $password, $username, $validationUrl, $userLocale, $groups);
            return json_decode(json_encode($result));
        } catch (\Exception $e) {
            Log::addInfo('Couldnt create user');
            throw new UserManagementException('unknown');
        }
    }

    public function updateUser($root, $args, $context)
    {
        $sani = App::make('helper/security');
        $ip_service = App::make('ip');
        $adminArray = Config::get('concrete5_graphql_websocket_security::graphql_jwt.adminArray');

        if (!is_array($adminArray)) {
            $adminArray = ['admin'];
        }

        if ($ip_service->isBlacklisted()) {
            Log::addInfo('IP Blacklisted');
            throw new \Exception($ip_service->getErrorMessage());
        }

        try {
            $username = $sani->sanitizeString($args['username']);
            $contextUsername = $context['user']->uName;
            $email = $sani->sanitizeString($args['email']);
            $userLocale = $sani->sanitizeString($args['userLocale']);
            $groups = $args['groups'];
            
            if (!HasAccess::checkByGroup($context, $adminArray) && $username !== $contextUsername) {
                Log::addInfo('Not allowed to update user: ' . $contextUsername);
                throw new UserManagementException('unknown');
            }
            //check for existing user
            $userInfo = App::make(UserInfoRepository::class)->getByName($username);

            if (!$userInfo) {
                Log::addInfo('Existing user not found: ' . $username);
                throw new UserManagementException('user_not_found');
            }

            //update user
            $user = App::make(User::class);
            $validationUrl = $sani->sanitizeURL($args['validationUrl']);
            $result = $user->update($userInfo, $email, $validationUrl, $userLocale, $groups);
            return json_decode(json_encode($result));
        } catch (\Exception $e) {
            Log::addInfo('Couldnt update user');
            throw new UserManagementException('unknown');
        }
    }

    public function sendValidationEmail($root, $args, $context)
    {
        $sani = App::make('helper/security');
        $reCaptchaToken = $sani->sanitizeString($args['reCaptchaToken']);

        $ip_service = App::make('ip');
        if ($ip_service->isBlacklisted()) {
            Log::addInfo('IP Blacklisted');
            throw new \Exception($ip_service->getErrorMessage());
        }

        $captcha = App::make(\Helpers\GoogleRecaptchaCheck::class);
        if (!$captcha->check($reCaptchaToken, 'validationEmail')) {
            Log::addInfo('Captcha not valid');
            throw new UserManagementException('unknown');
        }

        $uName = $sani->sanitizeString($args['uName']);
        $validationUrl = $sani->sanitizeURL($args['validationUrl']);
        $ui = App::make(UserInfoRepository::class)->getByUserName($uName);
        if (is_object($ui) && !$ui->isError()) {
            //send validation email
            App::make(StatusService::class)->sendEmailValidation($ui, $validationUrl);
            return true;
        } else {
            Log::addInfo('Couldnt send validation email to ' . $uName);
            throw new UserManagementException('unknown');
        }
    }

    public function validateEmail($root, $args, $context)
    {
        $sani = App::make('helper/security');
        $token = $sani->sanitizeString($args['token']);
        $ui = $ui = App::make(UserInfoRepository::class)->getByValidationHash($token);
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
