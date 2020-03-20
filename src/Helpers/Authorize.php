<?php

namespace Helpers;

use Concrete\Core\Support\Facade\Application as App;
use Symfony\Component\HttpFoundation\JsonResponse;
use Concrete\Core\Error\UserMessageException;
use Core;
use User;
use UserInfo;
use Config;
use Exception;
use TsaModels\Authenticator as Authenticator;
use TsaModels\SettingsManager as SettingsManager;

class Authorize
{
    protected $issued;
    protected $expiration;
    protected $isRefreshToken = false;

    /**
     * Get the user and password in the request body and generat a JWT
     *
     * @param string $username
     * @param string $password
     *
     * @return mixed
     * @throws \Exception
     * @since 0.0.1
     */
    public function loginAndGetToken($username, $password)
    {
        $accessToken = '';
        $nonce = '';
        $token = '';
        $error = '';

        try {
            $authenticate = App::make(\Helpers\Authenticate::class);
            //get user without login
            $user = new User($username, $password, true);

            if (is_object($user) && ($user instanceof User) && !$user->isError()) {
                $userInfo = $user->getUserInfoObject();
                $tsa = $userInfo->getAttribute('two_step_auth_data');
                if (!$tsa || !is_object($tsa) || !$tsa->getActivateTwoStep()) {
                    $user = $authenticate->authenticateUser($username, $password);
                    $tokenClass = App::make(\Helpers\Token::class);
                    $accessToken = $tokenClass->createAccessToken($user);
                    $tokenClass->sendRefreshAccessToken($user);
                } else {
                    // user name and password were correct, let's create a token and save it in a user attribute
                    $rand = Core::make('helper/validation/identifier')->getString(10);
                    $nonce = str_replace(' ', '', $rand . $user->getUserID() . microtime());

                    $token = Core::make('token')->generate($nonce);
                    // save $nonce in user attribute
                    $userInfo->setAttribute('tsa_login_nonce', $nonce);
                }
            }
        } catch (\Exception $e) {
            $error = $e->getMessage();
        }

        return ['error' => $error, 'authToken' => $accessToken, 'nonce' => $token];
    }

    public function checkNonce($user, $nonce, $u2SAPass)
    {
        $accessToken = '';
        $token = '';
        $error = '';
        $ip_service = Core::make('ip');
        $settingsManager = new settingsManager();

        try {
            // This is second screen with GA code
            if (!isset($user) || !isset($nonce) || !isset($u2SAPass)) {
                // somebody got here directly without going through the first screen so there are no user name and token
                throw new Exception(t('No user was defined. Please try again.'));
            }
            if (Config::get('concrete.user.registration.email_registration')) {
                $user = UserInfo::getByEmail($user)->getUserObject();
            } else {
                $user = UserInfo::getByUserName($user)->getUserObject();
            }

            // the user for that user name doesn't exist
            if (!is_object($user) || !($user instanceof User) || $user->isError()) {
                throw new Exception(t('Your session has expired. Please sign in again.'));
            }

            $post = [
                'checkGAPassword' => true,
                'u2SAPass' => $u2SAPass,
                'nonce' => $nonce,
                'user' => $user,
            ];
            // let's check the data: user and GA code
            $ret = Authenticator::processTokenForm($post, $user);
            // oups, nice try but no
            if ($ret['status'] === 'error') {
                // [TODO if set, use ip code to mark this as bad]
                $manageIpBlacklist = $settingsManager->getManageIpBlacklist();
                if ($manageIpBlacklist) {
                    $ip_service->logSignupRequest();
                    if ($ip_service->signupRequestThreshholdReached()) {
                        $ip_service->createIPBan();
                        throw new \Exception($ip_service->getErrorMessage());
                    }
                }
                throw new Exception($ret['returned']);
            } elseif ($ret['status'] === 'success') {
                $user = $ret['returned'];
                // Must log the user in before setting the cookie and returning to login controller
                $user = User::loginByUserID($user->getUserID());
                // code was good an all, make sure to set the cookie to keep logged in 2 weeks if necessary
                // lemonbrain: this is deactivated for us
                // if (isset($post['uMaintainLogin']) && $post['uMaintainLogin']) {
                //     $user->setAuthTypeCookie('concrete');
                // }
                $tokenClass = App::make(\Helpers\Token::class);
                $accessToken = $tokenClass->createAccessToken($user);
                $tokenClass->sendRefreshAccessToken($user);
            }
        } catch (\Exception $e) {
            $error = $e->getMessage();
        }

        return ['error' => $error, 'authToken' => $accessToken, 'none' => $token];
    }

    public function loginAndGetTokenFromAnonymus()
    {
        $authenticate = App::make(\Helpers\Authenticate::class);
        $user = $authenticate->authenticateAnonymus();

        $token = App::make(\Helpers\Token::class);
        $accessToken = $token->createAccessToken($user);
        $token->sendRefreshAccessToken($user);

        return !empty($accessToken) ? $accessToken : null;
    }

    public function logout()
    {
        $token = App::make(\Helpers\Token::class);
        $token->clearRefreshAccessToken();
        $authenticate = App::make(\Helpers\Authenticate::class);
        $returnValue = $authenticate->deauthenticateUser();


        $config = App::make('config');
        if ((bool) $config->get('concrete5_graphql_websocket_security::graphql_jwt.just_with_valid_token') && $returnValue) {
            try {
                $anonymusToken = $this->loginAndGetTokenFromAnonymus();
            } catch (\Exception $e) {
                return ['error' => $e->getMessage(), 'authToken' => ''];
            }

            return ['error' => '', 'authToken' => $anonymusToken];
        }

        return $returnValue ? ['error' => false, 'authToken' => true] : ['error' => true, 'authToken' => false];
    }

    public function logoutToken()
    {
        return new JsonResponse($this->logout());
    }

    public function authenticated()
    {
        $token = App::make(\Helpers\Token::class);
        $validatedToken = $token->validateAccess();

        if ($validatedToken) {
            $authenticate = App::make(\Helpers\Authenticate::class);
            return $authenticate->getUserByToken($validatedToken);
        }
        throw new \UserMessageException(t('Unauthenticated!'), 401);
        return false;
    }

    public function refreshToken()
    {
        try {
            $token = App::make(\Helpers\Token::class);
            $validatedToken = $token->validateRefreshAccess();
            if ($validatedToken) {
                $authenticate = App::make(\Helpers\Authenticate::class);
                $user = $authenticate->getUserByToken($validatedToken);

                $accessToken = $token->createAccessToken($user);
                $token->sendRefreshAccessToken($user);
            } else {
                return $this->logoutToken();
            }
        } catch (\Exception $e) {
            return new JsonResponse(['error' => $e->getMessage(), 'authToken' => '']);
        }

        return new JsonResponse(['error' => '', 'authToken' => $accessToken]);
    }


    /**
     * Given a user ID, if the ID is for a valid user and the current user has proper capabilities, this revokes
     * the JWT Secret from the user.
     *
     * @param User|AnonymusUser $user
     *
     * @return mixed|boolean|\Exception
     */
    public function revokeUserSecret($user)
    {
        $authenticate = App::make(\Helpers\Authenticate::class);
        return $authenticate->setRevoked($user, true);
    }

    /**
     * Given a user ID, if the ID is for a valid user and the current user has proper capabilities, this unrevokes
     * the JWT Secret from the user.
     *
     * @param User|AnonymusUser $user
     *
     * @return mixed|boolean|\Exception
     */
    public function unrevokeUserSecret($user)
    {
        $authenticate = App::make(\Helpers\Authenticate::class);
        return $authenticate->setRevoked($user, false);
    }
}
