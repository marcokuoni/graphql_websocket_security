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
use Concrete\Core\User\PersistentAuthentication;
use Concrete\Core\Validator\String\EmailValidator;
use Concrete\Core\User\ValidationHash;
use Symfony\Component\HttpFoundation\JsonResponse;
use Config;
use Core;
use Session;
use Database;
use Permissions;
use View;
use Log;

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
    public function authenticateUser($username, $password)
    {
        /** @var \Concrete\Core\Permission\IPService $ip_service */
        $ip_service = Core::make('ip');
        if ($ip_service->isBlacklisted()) {
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
            throw new UserMessageException(t('Unknown login error occurred. Please try again.'));
        }

        $loginService->logLoginAttempt($username);

        return !empty($user) ? $user : null;
    }

    public function authenticateAnonymus()
    {
        /** @var \Concrete\Core\Permission\IPService $ip_service */
        $ip_service = Core::make('ip');
        if ($ip_service->isBlacklisted()) {
            throw new \Exception($ip_service->getErrorMessage());
        }

        $currentUser = $this->getCurrentUser();
        if ($currentUser) {
            $this->deauthenticateUser();
        }

        return null;
    }

    public function deauthenticateUser()
    {
        $currentUser = $this->getCurrentUser();
        if ($currentUser) {
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

    public function forgotPassword($username, $currentLanguage)
    {
        $error = App::make('helper/validation/error');

        if ($username) {
            try {
                $e = App::make('error');
                if (!App::make(EmailValidator::class)->isValid($username, $e)) {
                    throw new \Exception($e->toText());
                }

                $oUser = UserInfo::getByEmail($username);
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
                    $changePassURL = View::url("/#!/{$currentLanguage}/auth/change-password/{$uHash}");

                    $mh->addParameter('changePassURL', $changePassURL);

                    $fromEmail = (string) Config::get('concrete.email.forgot_password.address');
                    if (!strpos($fromEmail, '@')) {
                        $adminUser = UserInfo::getByID(USER_SUPER_ID);
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

    public function changePassword($password, $passwordConfirm, $token)
    {
        $e = Core::make('helper/validation/error');
        if (is_string($token)) {
            $ui = UserInfo::getByValidationHash($token);
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
        return $e->getList();
    }

    protected function handleFailedLogin(LoginService $loginService, $username, $password, UserException $e)
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
    public function invalidateSession($hard = true)
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
                $config->get('concrete.session.cookie.cookie_httponly')
            );
        }

        $loginCookie = sprintf('%s_LOGIN', $app['config']->get('concrete.session.name'));
        if ($cookie->has($loginCookie) && $cookie->get($loginCookie)) {
            $cookie->clear($loginCookie, 1);
        }
    }

    public function setSecret($user, $secret)
    {
        if (!$user) {
            $anonymusUser = App::make(AnonymusUser::class);
            $anonymusUser->setSecret($secret);
        } else {
            $userInfo = $user->getUserInfoObject();
            $userInfo->setAttribute("graphql_jwt_auth_secret", $secret);
        }
    }

    public function getSecret($user)
    {
        $secret = null;

        if (!$user) {
            $anonymusUser = App::make(AnonymusUser::class);
            $secret = $anonymusUser->getSecret();
        } else {
            if (0 !== (int) $user->getUserID()) {
                $userInfo = $user->getUserInfoObject();
                $secret = $userInfo->getAttribute("graphql_jwt_auth_secret");
            }
        }

        return $secret;
    }

    public function setRefreshCount($user, $count)
    {
        if (!$user) {
            $anonymusUser = App::make(AnonymusUser::class);
            $anonymusUser->setRefreshCount($count);
        } else {
            $up = new Permissions(UserInfo::getByID($user->getUserID()));
            if (0 !== (int) $user->getUserID() && $up->canEditUser()) {
                $userInfo = $user->getUserInfoObject();
                $userInfo->setAttribute("graphql_jwt_auth_refresh_count", $count);
            }
        }
    }

    public function getRefreshCount($user)
    {
        $count = null;

        if (!$user) {
            $anonymusUser = App::make(AnonymusUser::class);
            $count = $anonymusUser->getRefreshCount();
        } else {
            if (0 !== (int) $user->getUserID()) {
                $userInfo = $user->getUserInfoObject();
                $count = $userInfo->getAttribute("graphql_jwt_auth_refresh_count");
            }
        }

        return $count;
    }

    public function setRevoked($user, $revoked)
    {
        if (!$user) {
            $anonymusUser = App::make(AnonymusUser::class);
            $anonymusUser->setRevoked($revoked);

            return true;
        } else {
            $up = new Permissions(UserInfo::getByID($user->getUserID()));
            if (0 !== (int) $user->getUserID() && $up->canEditUser()) {
                $userInfo = $user->getUserInfoObject();
                $userInfo->setAttribute("graphql_jwt_auth_secret_revoked", $revoked);

                return true;
            }
        }
    }

    public function getRevoked($user)
    {
        $revoked = null;

        if (!$user) {
            $anonymusUser = App::make(AnonymusUser::class);
            $revoked = $anonymusUser->getRevoked();
        } else {
            if (0 !== (int) $user->getUserID()) {
                $userInfo = $user->getUserInfoObject();
                $revoked = $userInfo->getAttribute("graphql_jwt_auth_secret_revoked");
            }
        }

        return isset($revoked) && true === $revoked ? true : false;
    }

    public function setTokenExpires($user, $expires)
    {
        if (!$user) {
            $anonymusUser = App::make(AnonymusUser::class);
            $anonymusUser->setTokenExpires($expires);
        } else {
            $up = new Permissions(UserInfo::getByID($user->getUserID()));
            if (0 !== (int) $user->getUserID() && $up->canEditUser()) {
                $userInfo = $user->getUserInfoObject();
                $userInfo->setAttribute("graphql_jwt_token_expires", $expires);
            }
        }
    }

    public function setRefreshTokenExpires($user, $expires)
    {
        if (!$user) {
            $anonymusUser = App::make(AnonymusUser::class);
            $anonymusUser->setRefreshTokenExpires($expires);
        } else {
            $up = new Permissions(UserInfo::getByID($user->getUserID()));
            if (0 !== (int) $user->getUserID() && $up->canEditUser()) {
                $userInfo = $user->getUserInfoObject();
                $userInfo->setAttribute("graphql_jwt_refresh_token_expires", $expires);
            }
        }
    }

    public function getNotBefore($user)
    {
        $notBefore = 0;

        if (!$user) {
            $anonymusUser = App::make(AnonymusUser::class);
            $notBefore = $anonymusUser->getNotBefore();
        } else {
            if (0 !== (int) $user->getUserID()) {
                $userInfo = $user->getUserInfoObject();
                $notBefore = $userInfo->getAttribute("graphql_jwt_token_not_before");
            }
        }

        return $notBefore;
    }

    public function getUserByToken($token)
    {
        //Just give access to the current session user
        return $this->getCurrentUser();
    }

    public function getCurrentUser()
    {
        $currentUser = App::make(User::class);

        if (empty($currentUser) || $currentUser->getUserID() === null) {
            $currentUser = null;
        }

        return $currentUser;
    }

    public function logRequest($user)
    {
        $config = App::make('config');
        if ((bool) $config->get('concrete5_graphql_websocket_security::graphql_jwt.log_requests')) {
            $ipService = App::make(IPService::class);
            $request = App::make(ConcreteRequest::class);
            $ip = (string) $ipService->getRequestIPAddress();
            $timezone = date_default_timezone_get();
            $language = Localization::activeLocale();
            $currentTime = time();
            $userAgent = $request->server->get('HTTP_USER_AGENT');

            if ((int) $user->getUserID() > 0) {
                $userInfo = $user->getUserInfoObject();
                $userInfo->setAttribute("graphql_jwt_last_request", $currentTime);
                $userInfo->setAttribute("graphql_jwt_last_request_ip", $ip);
                $userInfo->setAttribute("graphql_jwt_last_request_agent", $userAgent);
                $userInfo->setAttribute("graphql_jwt_last_request_timezone", $timezone);
                $userInfo->setAttribute("graphql_jwt_last_request_language", $language);
                $userInfo->setAttribute(
                    "graphql_jwt_request_count",
                    $userInfo->getAttribute("graphql_jwt_request_count") > 0 ? ($userInfo->getAttribute("graphql_jwt_request_count") + 1) : 1
                );
            }
        }
    }
}
