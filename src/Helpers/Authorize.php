<?php

namespace Helpers;

use Concrete\Core\Support\Facade\Application as App;
use Symfony\Component\HttpFoundation\JsonResponse;
use Concrete\Core\Support\Facade\Application as Core;
use Concrete\Core\User\User;
use Concrete\Core\Support\Facade\UserInfo;
use Concrete\Core\Support\Facade\Config;
use TsaModels\Authenticator as Authenticator;
use TsaModels\SettingsManager as SettingsManager;
use Log;
use Helpers\SecurityException;
use Siler\Http\Request;

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
    public function loginAndGetToken(string $username, string $password, string $reCaptchaToken): array
    {
        $accessToken = '';
        $nonce = '';
        $token = '';
        $authError = null;

        try {
            $captcha = App::make(\Helpers\GoogleRecaptchaCheck::class);
            if (!$captcha->check($reCaptchaToken, 'login')) {
                Log::addInfo('Login captcha not valid');
                throw new SecurityException('unknown');
            }

            $authenticate = App::make(\Helpers\Authenticate::class);
            //get user without login
            $user = new User($username, $password, true);

            if (is_object($user) && ($user instanceof User) && !$user->isError()) {
                $userInfo = $user->getUserInfoObject();
                $tsa = $userInfo->getAttribute('two_step_auth_data');
                if (!$tsa || !is_object($tsa) || !$tsa->getActivateTwoStep()) {
                    $user = $authenticate->authenticateUser($username, $password);
                    $tokenHelper = App::make(\Helpers\Token::class);
                    $accessToken = $tokenHelper->createAccessToken($user);
                    $tokenHelper->sendRefreshAccessToken($user);
                } else {
                    // user name and password were correct, let's create a token and save it in a user attribute
                    $rand = Core::make('helper/validation/identifier')->getString(10);
                    $nonce = str_replace(' ', '', $rand . $user->getUserID() . microtime());

                    $token = Core::make('token')->generate($nonce);
                    // save $nonce in user attribute
                    $userInfo->setAttribute('tsa_login_nonce', $nonce);
                }
            }

            if ($user->isError()) {
                $error = $user->getError();
                Log::addDebug($error);
                if ($error === USER_NON_VALIDATED) {
                    $ui = App::make('\Concrete\Core\User\UserInfoRepository')->getByEmail($username);
                    $authError = [
                        'type' => 'user_non_validated',
                        'uName' => $ui->getUserName()
                    ];
                } else {
                    throw new SecurityException('unknown_login_error');
                }
            }
        } catch (\Exception $e) {
            throw new SecurityException('unknown_login_error');
        }

        return ['authError' => $authError, 'authToken' => $accessToken, 'nonce' => $token];
    }

    public function checkNonce(string $user, string $nonce, string $u2SAPass, string $reCaptchaToken): array
    {
        $accessToken = '';
        $token = '';
        $error = '';
        $ip_service = Core::make('ip');
        $settingsManager = new SettingsManager();

        try {
            $captcha = App::make(\Helpers\GoogleRecaptchaCheck::class);
            if (!$captcha->check($reCaptchaToken, 'checkNonce')) {
                Log::addInfo('check nonce captcha not valid');
                throw new SecurityException('unknown');
            }
            // This is second screen with GA code
            if (!isset($user) || !isset($nonce) || !isset($u2SAPass)) {
                // somebody got here directly without going through the first screen so there are no user name and token
                throw new \Exception(t('No user was defined. Please try again.'));
            }
            if (Config::get('concrete.user.registration.email_registration')) {
                $user = UserInfo::getByEmail($user)->getUserObject();
            } else {
                $user = UserInfo::getByUserName($user)->getUserObject();
            }

            // the user for that user name doesn't exist
            if (!is_object($user) || !($user instanceof User) || $user->isError()) {
                throw new \Exception(t('Your session has expired. Please sign in again.'));
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
                throw new \Exception($ret['returned']);
            } elseif ($ret['status'] === 'success') {
                $user = $ret['returned'];
                // Must log the user in before setting the cookie and returning to login controller
                $user = User::loginByUserID($user->getUserID());
                // code was good an all, make sure to set the cookie to keep logged in 2 weeks if necessary
                // lemonbrain: this is deactivated for us
                // if (isset($post['uMaintainLogin']) && $post['uMaintainLogin']) {
                //     $user->setAuthTypeCookie('concrete');
                // }
                $tokenHelper = App::make(\Helpers\Token::class);
                $accessToken = $tokenHelper->createAccessToken($user);
                $tokenHelper->sendRefreshAccessToken($user);
            }
        } catch (\Exception $e) {
            $error = $e->getMessage();
        }

        return ['error' => $error, 'authToken' => $accessToken, 'nonce' => $token];
    }

    public function logout(): bool
    {
        $tokenHelper = App::make(\Helpers\Token::class);
        $tokenHelper->clearRefreshAccessToken();
        $authenticate = App::make(\Helpers\Authenticate::class);
        $authenticate->deauthenticateUser();

        return true;
    }

    public function logoutThroughRest(): JsonResponse
    {
        $origins = Config::get('concrete5_graphql_websocket::graphql.corsOrigins');
        if(in_array($_SERVER['HTTP_ORIGIN'], $origins)) {
            header('Access-Control-Allow-Credentials: true');
            header('Access-Control-Max-Age: 86400');
            header('Access-Control-Allow-Origin', $_SERVER['HTTP_ORIGIN']);
            header('Access-Control-Allow-Headers', $_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS']);
            header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        }

        if (Request\method_is('options')) {
            return new JsonResponse(null, JsonResponse::HTTP_NO_CONTENT);
        } else {
            return new JsonResponse($this->logout(), JsonResponse::HTTP_OK);
        }
    }

    public function refreshToken(): JsonResponse
    {
        $origins = Config::get('concrete5_graphql_websocket::graphql.corsOrigins');
        if(in_array($_SERVER['HTTP_ORIGIN'], $origins)) {
            header('Access-Control-Allow-Credentials: true');
            header('Access-Control-Max-Age: 600');
            header('Access-Control-Allow-Origin', $_SERVER['HTTP_ORIGIN']);
            header('Access-Control-Allow-Headers', $_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS']);
            header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        }

        if (Request\method_is('options')) {
            return new JsonResponse(null, JsonResponse::HTTP_NO_CONTENT);
        } else if (Request\method_is('post')) {
            try {
                $tokenHelper = App::make(\Helpers\Token::class);
                $user = $tokenHelper->validateRefreshAccess();
                if ($user) {
                    $accessToken = $tokenHelper->createAccessToken($user);
                    $tokenHelper->sendRefreshAccessToken($user);
                } else {
                    $this->logout();
                    return new JsonResponse(['error' => 'Session Expired', 'authToken' => ''], JsonResponse::HTTP_UNAUTHORIZED);
                }
            } catch (\Exception $e) {
                return new JsonResponse(['error' => $e->getMessage(), 'authToken' => ''], JsonResponse::HTTP_UNAUTHORIZED);
            }

            return new JsonResponse(['error' => '', 'authToken' => $accessToken], JsonResponse::HTTP_NO_CONTENT);
        }
        
        $this->logout();
        return new JsonResponse(['error' => 'Session Expired', 'authToken' => ''], JsonResponse::HTTP_UNAUTHORIZED);
    }


    /**
     * Given a user ID, if the ID is for a valid user and the current user has proper capabilities, this revokes
     * the JWT Secret from the user.
     *
     * @param User|AnonymusUser $user
     *
     * @return mixed|boolean|\Exception
     */
    public function revokeUserSecret(User $user): bool
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
    public function unrevokeUserSecret(User $user): bool
    {
        $authenticate = App::make(\Helpers\Authenticate::class);
        return $authenticate->setRevoked($user, false);
    }
}
