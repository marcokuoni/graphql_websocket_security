<?php

namespace Helpers;

use Firebase\JWT\JWT;
use Concrete\Core\Support\Facade\Application as App;
use Concrete\Core\Error\UserMessageException;
use Zend\Http\PhpEnvironment\Request;
use Concrete\Core\User\UserInfoRepository;
use Concrete\Core\Cookie\ResponseCookieJar;

class Token
{
    public function createAccessToken($user)
    {
        $notBefore = $this->checkIfUserCanCreateToken($user);
        $token = $this->createToken($user, $notBefore, $this->getTokenExpiration());

        $authenticate = App::make(\Helpers\Authenticate::class);
        $authenticate->setTokenExpires($user, $token['exp']);

        JWT::$leeway = 60;
        $token       = JWT::encode($token, $this->getSecretKey());


        return !empty($token) ? $token : null;
    }

    public function sendRefreshAccessToken($user)
    {
        $refreshToken = $this->createRefreshToken($user);

        $config = App::make('config');
        $cookie_name = (string) $config->get('concrete5_graphql_websocket_security::graphql_jwt.cookie.cookie_name');
        $cookie_path = (string) $config->get('concrete5_graphql_websocket_security::graphql_jwt.cookie.cookie_path');
        $cookie_lifetime = (int)  gmmktime() + $config->get('concrete5_graphql_websocket_security::graphql_jwt.cookie.cookie_lifetime');
        $cookie_domain = (string) $config->get('concrete5_graphql_websocket_security::graphql_jwt.cookie.cookie_domain');
        $cookie_secure = (string) $config->get('concrete5_graphql_websocket_security::graphql_jwt.cookie.cookie_secure');
        $cookie_same_site = (string) $config->get('concrete5_graphql_websocket_security::graphql_jwt.cookie.cookie_same_site');
        $cookie_httponly = (string) $config->get('concrete5_graphql_websocket_security::graphql_jwt.cookie.cookie_httponly');
        $cookie_raw = (string) $config->get('concrete5_graphql_websocket_security::graphql_jwt.cookie.cookie_raw');

        // $cookie = App::make('cookie');
        App::make(ResponseCookieJar::class)->addCookie(
            $cookie_name,
            $refreshToken,
            $cookie_lifetime,
            $cookie_path,
            $cookie_domain,
            $cookie_secure,
            $cookie_httponly,
            $cookie_raw,
            $cookie_same_site,
        );
    }

    public function clearRefreshAccessToken()
    {
        $config = App::make('config');
        $cookie_name = (string) $config->get('concrete5_graphql_websocket_security::graphql_jwt.cookie.cookie_name');

        $cookie = App::make('cookie');
        $cookie->clear($cookie_name);
    }

    public function validateRefreshAccess()
    {
        //for user
        $config = App::make('config');
        $cookie_name = (string) $config->get('concrete5_graphql_websocket_security::graphql_jwt.cookie.cookie_name');

        $cookie = App::make('cookie');
        $refreshToken = $cookie->get(
            $cookie_name
        );

        return $this->validateToken($refreshToken, true);
    }

    private function createRefreshToken($user)
    {
        $authenticate = App::make(\Helpers\Authenticate::class);
        $notBefore = $this->checkIfUserCanCreateToken($user);
        $token = $this->createToken($user, $notBefore, $this->getRefreshTokenExpiration());

        $authenticate = App::make(\Helpers\Authenticate::class);
        $authenticate->setRefreshTokenExpires($user, $token['exp']);

        JWT::$leeway = 60;
        $token       = JWT::encode($token, $this->getRefreshSecretKey());

        return !empty($token) ? $token : null;
    }

    public function validateToken($token, $isRefresh = false)
    {
        $authenticate = App::make(\Helpers\Authenticate::class);
        $user = null;

        if (empty($token)) {
            return false;
        }

        $secret = '';
        if (!$isRefresh) {
            $secret = $this->getSecretKey();
        } else {
            $secret = $this->getRefreshSecretKey();
        }

        if (!$secret) {
            throw new UserMessageException(t('JWT is not configured properly'));
        }

        try {
            JWT::$leeway = 60;

            $token = !empty($token) ? JWT::decode($token, $secret, ['HS256']) : null;

            $baseUrl = sprintf(
                "%s://%s",
                isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] != 'off' ? 'https' : 'http',
                $_SERVER['SERVER_NAME']
            );
            // websocketserver has no server_name
            if (isset($_SERVER['SERVER_NAME']) && $baseUrl !== $token->iss) {
                throw new \Exception(t('The iss do not match with this server'));
            }

            $user = $authenticate->getUserByToken($token);

            if (!isset($token->data->user->user_secret) || $this->getUserJwtSecret($user) !== $token->data->user->user_secret) {
                throw new \Exception(t('The User Secret does not match or has been revoked for this user'));
            }
        } catch (\Exception $error) {
            if ($error->getMessage() === 'Expired token') {
                throw new UserMessageException(t('Expired token'), 401);
            } else {
                throw new UserMessageException(t('The JWT Token is invalid'), 401);
            }
        }

        return $user;
    }

    private function checkIfUserCanCreateToken($user)
    {
        $notBefore = $this->getNotBefore($user);

        if ($this->isJwtSecretRevoked($user)) {
            throw new \Exception(t('The JWT token cannot be issued for this user'));
        }

        return $notBefore;
    }

    private function createToken($user, $notBefore, $expiration)
    {
        $baseUrl = sprintf(
            "%s://%s",
            isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] != 'off' ? 'https' : 'http',
            $_SERVER['SERVER_NAME']
        );

        //https://tools.ietf.org/html/rfc7519#section-4.1

        $returnUser = [];
        if ($user) {
            $userInfo = App::make(UserInfoRepository::class)->getByID((int) $user->getUserID());
            $returnUser = [
                "uID" => $user->getUserID(),
                "uName" => $user->getUserName(),
                "uEmail" => $userInfo->getUserEmail(),
                "uGroupsPath" => array_map(function ($item) {
                    return $item->getGroupPath();
                }, $user->getUserGroupObjects()),
                "uAvatar" => $userInfo->getUserAvatar()->getPath()
            ];
        }

        $token = [
            'iss'  => $baseUrl,
            'iat'  => gmmktime(),
            'nbf'  => $notBefore,
            'exp'  => $expiration,
            'data' => [
                'user' => $returnUser
            ],
        ];

        $secret = $this->getUserJwtSecret($user);
        if (!empty($secret)) {
            $token['data']['user']['user_secret'] = $secret;
        }

        return $token;
    }

    private function getNotBefore($user)
    {
        $authenticate = App::make(\Helpers\Authenticate::class);
        $notBefore = $authenticate->getNotBefore($user);

        return $notBefore > 0 ? $notBefore : gmmktime();
    }

    /**
     * Returns the expiration for the token
     *
     * @return mixed|string|null
     */
    private function getTokenExpiration()
    {
        $config = App::make('config');
        $expirationConfig = (int) $config->get('concrete5_graphql_websocket_security::graphql_jwt.auth_expire');

        if ($expirationConfig > 0) {
            return gmmktime() + $expirationConfig;
        } else {
            return gmmktime() + 300;
        }
    }

    /**
     * Returns the expiration for the refresh token
     *
     * @return mixed|string|null
     */
    private function getRefreshTokenExpiration()
    {
        $config = App::make('config');
        $expirationConfig = (int) $config->get('concrete5_graphql_websocket_security::graphql_jwt.auth_refresh_expire');

        if ($expirationConfig > 0) {
            return gmmktime() + $expirationConfig;
        } else {
            return gmmktime() + (86400 * 365);
        }
    }

    /**
     * Given a User ID, returns the user's JWT secret
     *
     * @param User $user
     *
     * @return mixed|string
     */
    private function getUserJwtSecret($user)
    {
        $authenticate = App::make(\Helpers\Authenticate::class);

        if (true === $this->isJwtSecretRevoked($user)) {
            if (!empty($currentUser)) {
                throw new UserMessageException(t('The JWT Auth secret cannot be returned'));
            }
        }

        $secret = $authenticate->getSecret($user);

        if (empty($secret) || !is_string($secret)) {
            $this->issueNewUserSecret($user);
            $secret = $authenticate->getSecret($user);
        }

        /**
         * Return the $secret
         *
         * @param string $secret  The GraphQL JWT Auth Secret associated with the user
         * @param int    $userId The ID of the user the secret is associated with
         */
        return $secret;
    }

    /**
     * Given a User, returns whether their JWT secret has been revoked or not.
     *
     * @param User $user
     *
     * @return bool
     */
    private function isJwtSecretRevoked($user)
    {
        $authenticate = App::make(\Helpers\Authenticate::class);
        return $authenticate->getRevoked($user);
    }

    /**
     * Given a User ID, issue a new JWT Auth Secret
     *
     * @param User $user The user the secret is being issued for
     *
     * @return string $secret The JWT User secret for the user.
     */
    private function issueNewUserSecret($user)
    {
        if (!$this->isJwtSecretRevoked($user)) {
            $authenticate = App::make(\Helpers\Authenticate::class);
            $secret = $authenticate->getSecret($user) ? $authenticate->getSecret($user) : uniqid('graphql_jwt_');
            $authenticate->setSecret($user, $secret);
        }
    }

    /**
     * This returns the secret key, using the defined constant if defined, and passing it through a filter to
     * allow for the config to be able to be set via another method other than a defined constant, such as an
     * admin UI that allows the key to be updated/changed/revoked at any time without touching server files
     *
     * @return mixed|null|string
     * @since 0.0.1
     */
    private function getSecretKey()
    {
        $config = App::make('config');
        $secret_key = (string) $config->get('concrete5_graphql_websocket_security::graphql_jwt.auth_secret_key');


        if (empty($secret_key)) {
            throw new UserMessageException(t('JWT Auth is not configured correctly. Please contact a site administrator.'));
        }
        return $secret_key;
    }

    /**
     * This returns the secret key, using the defined constant if defined, and passing it through a filter to
     * allow for the config to be able to be set via another method other than a defined constant, such as an
     * admin UI that allows the key to be updated/changed/revoked at any time without touching server files
     *
     * @return mixed|null|string
     * @since 0.0.1
     */
    private function getRefreshSecretKey()
    {
        $config = App::make('config');
        $secret_key = (string) $config->get('concrete5_graphql_websocket_security::graphql_jwt.auth_refresh_secret_key');

        if (empty($secret_key)) {
            throw new UserMessageException(t('JWT Auth is not configured correctly. Please contact a site administrator.'));
        }
        return $secret_key;
    }
}
