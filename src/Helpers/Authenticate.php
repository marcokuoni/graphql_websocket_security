<?php

namespace Helpers;

use Concrete\Core\Support\Facade\Application as App;
use Concrete\Core\User\Login\LoginService;
use Concrete\Core\User\Exception\FailedLoginThresholdExceededException;
use Concrete\Core\User\Exception\UserDeactivatedException;
use Concrete\Core\User\Exception\UserException;
use Concrete\Core\User\Exception\UserPasswordResetException;
use Concrete\Core\Error\UserMessageException;
use Entity\AnonymusUser as AnonymusUserEntity;
use Concrete\Core\Localization\Localization;
use Concrete\Core\Http\Request as ConcreteRequest;
use Concrete\Core\Permission\IPService;
use Concrete\Core\User\User;
use Concrete\Core\User\UserInfo;
use Concrete\Core\User\PersistentAuthentication;
use Core;
use Session;
use Database;
use Permissions;

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
            $currentAndMaybeOldUser = $this->getCurrentUser();

            $user = $loginService->login($username, $password);

            if (!empty($currentAndMaybeOldUser) && get_class($currentAndMaybeOldUser) !== AnonymusUserEntity::class && !empty($user)) {
                $anonymusUser = App::make(AnonymusUser::class);
                $anonymusUser->delete($currentAndMaybeOldUser);
            }
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
        if (!empty($currentUser) && get_class($currentUser) !== AnonymusUserEntity::class) {
            $this->deauthenticateUser();
        }

        $anonymusUser = App::make(\Helpers\AnonymusUser::class);
        if (empty($currentUser) || $currentUser->getUserID() === null) {
            $user = $anonymusUser->getAnonymusUser();
        } else {
            $user = $currentUser;
        }

        return !empty($user) ? $user : null;
    }

    public function deauthenticateUser()
    {
        $currentUser = $this->getCurrentUser();
        if (!empty($currentUser) && get_class($currentUser) !== AnonymusUserEntity::class) {
            $currentUser->logout();
        }

        $cookie = array_get($_COOKIE, 'ccmAuthUserHash', '');
        if ($cookie) {
            list($uID, $authType, $hash) = explode(':', $cookie);
            if ($authType == 'concrete') {
                $db = Database::connection();
                $db->executeQuery('DELETE FROM authTypeConcreteCookieMap WHERE uID=? AND token=?', [$uID, $hash]);
            }
        }

        $this->invalidateSession();

        return true;
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

    private function invalidateSession($hard = true)
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

        $app->make(PersistentAuthentication\CookieService::class)->deleteCookie();

        $loginCookie = sprintf('%s_LOGIN', $app['config']->get('concrete.session.name'));
        if ($cookie->has($loginCookie) && $cookie->get($loginCookie)) {
            $cookie->clear($loginCookie, 1);
        }
    }

    public function setSecret($user, $secret)
    {
        if (get_class($user) === AnonymusUserEntity::class) {
            if (0 !== (Int)$user->getUserID()) {
                $anonymusUser = App::make(AnonymusUser::class);
                $anonymusUser->setSecret($user, $secret);
            }
        } else {
            $up = new Permissions(UserInfo::getByID($user->getUserID()));
            if (0 !== (Int)$user->getUserID() && $up->canEditUser()) {
                $userInfo = $user->getUserInfoObject();
                $userInfo->setAttribute("graphql_jwt_auth_secret", $secret);
            }
        }
    }

    public function getSecret($user)
    {
        $secret = null;

        if (get_class($user) === AnonymusUserEntity::class) {
            if (0 !== (Int)$user->getUserID()) {
                $anonymusUser = App::make(AnonymusUser::class);
                $secret = $anonymusUser->getSecret($user);
            }
        } else {
            if (0 !== (Int)$user->getUserID()) {
                $userInfo = $user->getUserInfoObject();
                $secret = $userInfo->getAttribute("graphql_jwt_auth_secret");
            }
        }

        return $secret;
    }

    public function setRevoked($user, $revoked)
    {
        $currentUser = $this->getCurrentUser();
        if ((Int)$currentUser->getUserID() === (Int)$user->getUserID()) {
            if (get_class($user) === AnonymusUserEntity::class) {
                if (0 !== $user->getUserID()) {
                    $anonymusUser = App::make(AnonymusUser::class);
                    $anonymusUser->setRevoked($user, $revoked);

                    $this->issueNewUserSecret($user);

                    return true;
                }
            } else {
                $up = new Permissions(UserInfo::getByID($user->getUserID()));
                if (0 !== (Int)$user->getUserID() && $up->canEditUser()) {
                    $userInfo = $user->getUserInfoObject();
                    $userInfo->setAttribute("graphql_jwt_auth_secret_revoked", $revoked);

                    $this->issueNewUserSecret($user);

                    return true;
                }
            }
        } else {
            throw new \Exception(t('The JWT Auth Secret cannot be revoked for this user'));
        }
    }

    public function getRevoked($user)
    {
        $revoked = null;

        if (get_class($user) === AnonymusUserEntity::class) {
            if (0 !== (Int)$user->getUserID()) {
                $anonymusUser = App::make(AnonymusUser::class);
                $revoked = $anonymusUser->getRevoked($user);
            }
        } else {
            if (0 !== (Int)$user->getUserID()) {
                $userInfo = $user->getUserInfoObject();
                $revoked = $userInfo->getAttribute("graphql_jwt_auth_secret_revoked");
            }
        }

        return isset($revoked) && true === $revoked ? true : false;
    }

    public function setTokenExpires($user, $expires)
    {
        if (get_class($user) === AnonymusUserEntity::class) {
            if (0 !== (Int)$user->getUserID()) {
                $anonymusUser = App::make(AnonymusUser::class);
                $anonymusUser->setTokenExpires($user, $expires);
            }
        } else {
            $up = new Permissions(UserInfo::getByID($user->getUserID()));
            if (0 !== (Int)$user->getUserID() && $up->canEditUser()) {
                $userInfo = $user->getUserInfoObject();
                $userInfo->setAttribute("graphql_jwt_token_expires", $expires);
            }
        }
    }

    public function setRefreshTokenExpires($user, $expires)
    {
        if (get_class($user) === AnonymusUserEntity::class) {
            if (0 !== (Int)$user->getUserID()) {
                $anonymusUser = App::make(AnonymusUser::class);
                $anonymusUser->setRefreshTokenExpires($user, $expires);
            }
        } else {
            $up = new Permissions(UserInfo::getByID($user->getUserID()));
            if (0 !== (Int)$user->getUserID() && $up->canEditUser()) {
                $userInfo = $user->getUserInfoObject();
                $userInfo->setAttribute("graphql_jwt_refresh_token_expires", $expires);
            }
        }
    }

    public function getNotBefore($user)
    {
        $notBefore = 0;

        if (get_class($user) === AnonymusUserEntity::class) {
            if (0 !== (Int)$user->getUserID()) {
                $anonymusUser = App::make(AnonymusUser::class);
                $notBefore = $anonymusUser->getNotBefore($user);
            }
        } else {
            if (0 !== (Int)$user->getUserID()) {
                $userInfo = $user->getUserInfoObject();
                $notBefore = $userInfo->getAttribute("graphql_jwt_token_not_before");
            }
        }

        return $notBefore;
    }

    public function getUserByToken($token)
    {
        if ($token->data->user->anonymus) {
            $anonymusUser = App::make(\Helpers\AnonymusUser::class);
            return $anonymusUser->getAnonymusUser($token->data->user->uID);
        } else {
            //return User::getByUserID($token->data->user->uID);
            //Just give access to the current session user
            return App::make(User::class);
        }
    }

    public function getCurrentUser()
    {
        $currentUser = App::make(User::class);

        $anonymusUser = App::make(\Helpers\AnonymusUser::class);
        if (empty($currentUser) || $currentUser->getUserID() === null) {
            $currentUser = $anonymusUser->getAnonymusUser();
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

            if (get_class($user) === AnonymusUserEntity::class) {
                $anonymusUser = App::make(AnonymusUser::class);
                $anonymusUser->logRequest($user, $currentTime, $ip, $userAgent, $timezone, $language);
            } else if ((int)$user->getUserID() > 0) {
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
