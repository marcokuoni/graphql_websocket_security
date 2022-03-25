<?php

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
use Concrete\Core\User\User;
use Concrete\Core\User\UserInfo;
use Concrete\Core\Validator\String\EmailValidator;
use Concrete\Core\User\ValidationHash;
use Concrete\Core\Support\Facade\Config;
use Concrete\Core\Support\Facade\Application as Core;
use Concrete\Core\Support\Facade\Session;
use Concrete\Core\Support\Facade\Database;
use Concrete\Core\Permission\Checker as Permissions;
use Concrete\Core\Support\Facade\Log;

class Authenticate
{
    /**
     * Takes a username and password and authenticates the user and returns the authenticated user object
     *
     * @param string $username The username for the user to login
     * @param string $password The password for the user to login
     *
     * @return null|\Exception|User
     */
    public function authenticateUser(string $username, string $password): ?User
    {
        /** @var \Concrete\Core\Permission\IPService $ip_service */
        $ip_service = Core::make('ip');
        if ($ip_service->isBlacklisted()) {
            Log::addInfo('IP Blacklisted');
            throw new \Exception($ip_service->getErrorMessage());
        }

        $loginService = App::make(LoginService::class);

        try {
            $user = $loginService->login($username, $password);
        } catch (UserPasswordResetException $e) {
            Session::set('uPasswordResetUserName', $username);
        } catch (UserException $e) {
            $this->handleFailedLogin($loginService, $username, $password, $e);
        }

        if ($user->isError()) {
            Log::addInfo('Unknown login error occurred. Please try again.');
            throw new UserMessageException(t('Unknown login error occurred. Please try again.'));
        }

        $loginService->logLoginAttempt($username);

        return !empty($user) ? $user : null;
    }

    public function deauthenticateUser(): bool
    {
        $currentUser = App::make(User::class);

        if (!empty($currentUser)) {
            $currentUser->logout();

            $cookie = array_get($_COOKIE, 'ccmAuthUserHash', '');
            if ($cookie) {
                list($uID, $authType, $hash) = explode(':', $cookie);
                if ($authType == 'concrete') {
                    $db = Database::connection();
                    $db->executeQuery('DELETE FROM authTypeConcreteCookieMap WHERE uID=? AND token=?', [$uID, $hash]);
                }
            }

            $this->invalidateSession();
        }
        return true;
    }

    public function forgotPassword(string $username, string $changePasswordUrl, string $reCaptchaToken): array
    {
        $error = App::make('helper/validation/error');

        if ($username) {
            try {
                $captcha = App::make(\Helpers\GoogleRecaptchaCheck::class);
                if (!$captcha->check($reCaptchaToken, 'forgotPassword')) {
                    Log::addInfo('forgot password captcha not valid');
                    throw new SecurityException('unknown');
                }

                $e = App::make('error');
                if (!App::make(EmailValidator::class)->isValid($username, $e)) {
                    Log::addInfo('Email address not valid: ' . $e->toText());
                    throw new \Exception($e->toText());
                }

                // $oUser = UserInfo::getByEmail($username);
                $oUser = \Core::make('Concrete\Core\User\UserInfoRepository')->getByEmail($username);
                if ($oUser) {
                    $mh = App::make('helper/mail');
                    //$mh->addParameter('uPassword', $oUser->resetUserPassword());
                    if (Config::get('concrete.user.registration.email_registration')) {
                        $mh->addParameter('uName', $oUser->getUserEmail());
                    } else {
                        $mh->addParameter('uName', $oUser->getUserName());
                    }
                    $mh->to($oUser->getUserEmail());

                    //generate hash that'll be used to authenticate user, allowing them to change their password
                    $h = new ValidationHash();
                    $uHash = $h->add($oUser->getUserID(), intval(UVTYPE_CHANGE_PASSWORD), true);
                    Log::addDebug($uHash);
                    $changePassURL = "{$changePasswordUrl}/{$uHash}";

                    $mh->addParameter('changePassURL', $changePassURL);

                    $fromEmail = (string) Config::get('concrete.email.forgot_password.address');
                    if (!strpos($fromEmail, '@')) {
                        // $adminUser = UserInfo::getByID(USER_SUPER_ID);
                        $adminUser = \Core::make('Concrete\Core\User\UserInfoRepository')->getByID(USER_SUPER_ID);
                        if (is_object($adminUser)) {
                            $fromEmail = $adminUser->getUserEmail();
                        } else {
                            $fromEmail = '';
                        }
                    }
                    if ($fromEmail) {
                        $fromName = (string) Config::get('concrete.email.forgot_password.name');
                        if ($fromName === '') {
                            $fromName = t('Forgot Password');
                        }
                        $mh->from($fromEmail, $fromName);
                    }

                    $mh->addParameter('siteName', tc('SiteName', App::make('site')->getSite()->getSiteName()));
                    $mh->load('forgot_password');
                    @$mh->sendMail();
                }
            } catch (\Exception $e) {
                $error->add($e);
            }

            if ($error->has()) {
                return $error->getList();
            } else {
                return [];
            }
        }
    }

    public function changePassword(string $password, string $passwordConfirm, string $token, string $reCaptchaToken): array
    {
        $e = Core::make('helper/validation/error');

        try {
            $captcha = App::make(\Helpers\GoogleRecaptchaCheck::class);
            if (!$captcha->check($reCaptchaToken, 'changePassword')) {
                Log::addInfo('change password captcha not valid');
                throw new SecurityException('unknown');
            }

            if (is_string($token)) {
                // $ui = UserInfo::getByValidationHash($token);
                $ui = \Core::make('Concrete\Core\User\UserInfoRepository')->getByValidationHash($token);
            } else {
                $ui = null;
            }
            if (is_object($ui)) {
                $vh = new ValidationHash();
                if ($vh->isValid($token)) {
                    if (isset($password) && strlen($password)) {
                        Core::make('validator/password')->isValidFor($password, $ui, $e);

                        if (strlen($passwordConfirm) && $passwordConfirm !== $password) {
                            $e->add(t('The two passwords provided do not match.'));
                        }

                        if (!$e->has()) {
                            $ui->changePassword($password);
                            $h = Core::make('helper/validation/identifier');
                            $h->deleteKey('UserValidationHashes', 'uHash', $token);

                            return [];
                        }
                    }
                }
            } else {
                $e->add(t('token is no longer valid, get a new email.'));
            }
        } catch (\Exception $error) {
            $e->add($error->getMessage());
        }
        return $e->getList();
    }

    protected function handleFailedLogin(LoginService $loginService, string $username, string $password, UserException $e)
    {
        if ($e instanceof InvalidCredentialsException) {
            try {
                $loginService->failLogin($username, $password);
            } catch (FailedLoginThresholdExceededException $e) {
                $loginService->logLoginAttempt($username, ['Failed Login Threshold Exceeded', $e->getMessage()]);

                throw $e;
            } catch (UserDeactivatedException $e) {
                $loginService->logLoginAttempt($username, ['User Deactivated', $e->getMessage()]);

                throw $e;
            }
        }

        $loginService->logLoginAttempt($username, ['Invalid Credentials', $e->getMessage()]);

        throw $e;
    }

    /**
     * @param bool $hard
     */
    public function invalidateSession(bool $hard = true)
    {
        $app = App::getFacadeApplication();
        $session = $app['session'];
        $config = $app['config'];
        $cookie = $app['cookie'];

        // @todo remove this hard option if `Session::clear()` does what we need.
        if (!$hard) {
            $session->clear();
        } else {
            $session->invalidate();
            // Really not sure why this doesn't happen with invalidate, but oh well.
            $cookie->clear($config->get('concrete.session.name'));
        }

        if ($cookie->has('ccmAuthUserHash') && $cookie->get('ccmAuthUserHash')) {
            $cookie->set(
                'ccmAuthUserHash',
                '',
                315532800,
                DIR_REL . '/',
                $config->get('concrete.session.cookie.cookie_domain'),
                $config->get('concrete.session.cookie.cookie_secure'),
                $config->get('concrete.session.cookie.cookie_httponly'),
                $config->get('concrete.session.cookie.cookie_same_site'),
            );
        }

        $loginCookie = sprintf('%s_LOGIN', $app['config']->get('concrete.session.name'));
        if ($cookie->has($loginCookie) && $cookie->get($loginCookie)) {
            $cookie->clear($loginCookie, 1);
        }
    }

    public function setSecret(User $user, string $secret)
    {
        if ($user) {
            $userInfo = $user->getUserInfoObject();
            $userInfo->setAttribute("graphql_jwt_auth_secret", $secret);
        }
    }

    public function getSecret(User $user): string
    {
        $secret = null;

        if ($user) {
            if (0 !== (int) $user->getUserID()) {
                $userInfo = $user->getUserInfoObject();
                $secret = $userInfo->getAttribute("graphql_jwt_auth_secret");
            }
        }

        return $secret;
    }

    public function setRevoked(User $user, bool $revoked): bool
    {
        if ($user) {
            // $up = new Permissions(UserInfo::getByID($user->getUserID()));
            $up = new Permissions(\Core::make('Concrete\Core\User\UserInfoRepository')->getByID($user->getUserID()));
            if (0 !== (int) $user->getUserID() && $up->canEditUser()) {
                $userInfo = $user->getUserInfoObject();
                $userInfo->setAttribute("graphql_jwt_auth_secret_revoked", $revoked);

                return true;
            }
        }
        return false;
    }

    public function getRevoked(User $user): bool
    {
        $revoked = null;

        if ($user) {
            if (0 !== (int) $user->getUserID()) {
                $userInfo = $user->getUserInfoObject();
                $revoked = $userInfo->getAttribute("graphql_jwt_auth_secret_revoked");
            }
        }

        return isset($revoked) && true === $revoked ? true : false;
    }

    public function setTokenExpires(User $user, int $expires)
    {
        if ($user) {
            // $up = new Permissions(UserInfo::getByID($user->getUserID()));
            $up = new Permissions(\Core::make('Concrete\Core\User\UserInfoRepository')->getByID($user->getUserID()));
            if (0 !== (int) $user->getUserID() && $up->canEditUser()) {
                $userInfo = $user->getUserInfoObject();
                $userInfo->setAttribute("graphql_jwt_token_expires", $expires);
            }
        }
    }

    public function setRefreshTokenExpires(User $user, int $expires)
    {
        if ($user) {
            // $up = new Permissions(UserInfo::getByID($user->getUserID()));
            $up = new Permissions(\Core::make('Concrete\Core\User\UserInfoRepository')->getByID($user->getUserID()));
            if (0 !== (int) $user->getUserID() && $up->canEditUser()) {
                $userInfo = $user->getUserInfoObject();
                $userInfo->setAttribute("graphql_jwt_refresh_token_expires", $expires);
            }
        }
    }

    public function getNotBefore(User $user): int
    {
        $notBefore = 0;

        if ($user) {
            if (0 !== (int) $user->getUserID()) {
                $userInfo = $user->getUserInfoObject();
                $notBefore = (int) $userInfo->getAttribute("graphql_jwt_token_not_before");
            }
        }

        return $notBefore;
    }

    public function getUserByToken(object $token): ?User
    {
        $user = null;
        if ($token->data->user->uID > 0) {
            $user = User::getByUserID($token->data->user->uID);
        }
        return $user;
    }
}
