<?php

namespace Helpers;

use Concrete\Core\Support\Facade\Application as App;
use Concrete\Core\User\Login\LoginService;
use Concrete\Core\User\Exception\FailedLoginThresholdExceededException;
use Concrete\Core\User\Exception\UserDeactivatedException;
use Concrete\Core\User\Exception\UserException;
use Concrete\Core\User\Exception\UserPasswordResetException;
use Concrete\Core\Error\UserMessageException;
use Core;
use Session;
use Database;

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
            //$this->redirect('/login/', $this->getAuthenticationType()->getAuthenticationTypeHandle(), 'required_password_upgrade');
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

        $user = new \Helpers\User();

        return !empty($user) ? $user : null;
    }

    public function deauthenticateUser()
    {
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
        $app = Application::getFacadeApplication();
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
}
