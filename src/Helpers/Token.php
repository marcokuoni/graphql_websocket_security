<?php

namespace Helpers;

use Firebase\JWT\JWT;
use Firebase\JWT\ExpiredException;
use Concrete\Core\Support\Facade\Application as App;
use Concrete\Core\Error\UserMessageException;
use Zend\Http\PhpEnvironment\Request;

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
        $cookie_httponly = (string) $config->get('concrete5_graphql_websocket_security::graphql_jwt.cookie.cookie_httponly');

        $cookie = App::make('cookie');
        $cookie->set(
            $cookie_name,
            $refreshToken,
            $cookie_lifetime,
            $cookie_path,
            $cookie_domain,
            $cookie_secure,
            $cookie_httponly
        );
    }

    public function clearRefreshAccessToken()
    {
        $config = App::make('config');
        $cookie_name = (string) $config->get('concrete5_graphql_websocket_security::graphql_jwt.cookie.cookie_name');

        $cookie = App::make('cookie');
        $cookie->clear($cookie_name);

        $authenticate = App::make(\Helpers\Authenticate::class);
    }

    /**
     * Main validation function, this function try to get the Authentication
     * headers and decoded.
     *
     * @param string $token The encoded JWT Token
     *
     * @throws \Exception
     * @return User 
     */
    public function validateAccess()
    {
        $authHeader = $this->getAuthHeader();
        return $this->validateToken($authHeader);
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
        $authenticate->setRefreshCount($user, 0);
        $notBefore = $this->checkIfUserCanCreateToken($user);
        $token = $this->createToken($user, $notBefore, $this->getRefreshTokenExpiration());

        $authenticate = App::make(\Helpers\Authenticate::class);
        $authenticate->setRefreshTokenExpires($user, $token['exp']);

        JWT::$leeway = 60;
        $token       = JWT::encode($token, $this->getRefreshSecretKey());

        return !empty($token) ? $token : null;
    }

    private function validateToken($authHeader, $isRefresh = false)
    {
        if (empty($authHeader)) {
            return false;
        }

        if (!$isRefresh) {
            list($token) = sscanf($authHeader, 'Bearer %s');
            if (!isset($token)) {
                list($token) = sscanf($authHeader, 'Authorization: Bearer %s');
            }
        } else {
            $token = $authHeader;
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
            try {
                $token = !empty($token) ? JWT::decode($token, $secret, ['HS256']) : null;
            } catch (ExpiredException $e) {
                //if the token gets expired during transaction you can do a one time refresh
                $token = $this->checkForAutoRefresh($isRefresh, $secret);
            }

            $baseUrl = sprintf(
                "%s://%s",
                isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] != 'off' ? 'https' : 'http',
                $_SERVER['SERVER_NAME']
            );
            if ($baseUrl !== $token->iss) {
                throw new \Exception(t('The iss do not match with this server'));
            }

            $authenticate = App::make(\Helpers\Authenticate::class);
            $currentUser = $authenticate->getCurrentUser();

            if (!isset($token->data->user->user_secret) || $this->getUserJwtSecret($currentUser) !== $token->data->user->user_secret) {
                throw new \Exception(t('The User Secret does not match or has been revoked for this user'));
            }
        } catch (\Exception $error) {
            throw new UserMessageException(t('The JWT Token is invalid'), 401);
        }

        return $token;
    }

    /**
     * Get the value of the Authorization header from the $_SERVER super global
     *
     * @return mixed|string
     */
    private function getAuthHeader()
    {
        $request = new Request();
        $authHeader = $request->getHeader('authorization') ? $request->getHeader('authorization')->toString() : null;
        if (!isset($authHeader)) {
            $authHeader = isset($_SERVER['HTTP_AUTHORIZATION']) ? $_SERVER['HTTP_AUTHORIZATION'] : false;
        }
        $redirectAuthHeader = isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION']) ? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] : false;
        $authHeader = $authHeader !== false ? $authHeader : ($redirectAuthHeader !== false ? $redirectAuthHeader : null);

        return $authHeader;
    }

    private function checkIfUserCanCreateToken($user)
    {
        //only tokens for the person who is logged in at the moment
        $authenticate = App::make(\Helpers\Authenticate::class);
        $currentUser = $authenticate->getCurrentUser();
        if (!empty($currentUser)) {
            if (empty($user) || (int) $currentUser->getUserID() !== (int) $user->getUserID() || 0 === (int) $user->getUserID()) {
                throw new UserMessageException(t('Only the user requesting a token can get a token issued for them'));
            }
        }

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
            $returnUser = [
                "uID" => $user->getUserID(),
                "uName" => $user->getUserName(),
                "uGroups" => array_map(function ($item) {
                    return $item->getGroupDisplayName();
                }, $user->getUserObject()->getUserGroupObjects()),
                "uAvatar" => $user->getUserAvatar()->getPath()
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
     * @param User|AnonymusUser $user
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
     * @param User|AnonymusUser $user
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
     * @param User|AnonymusUser $user The user the secret is being issued for
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

    private function checkForAutoRefresh($isRefresh, $secret)
    {
        $config = App::make('config');
        $autoRefresh = (bool) $config->get('concrete5_graphql_websocket_security::graphql_jwt.one_time_auto_refresh');

        if ($autoRefresh && !$isRefresh) {
            try {
                $validatedToken = $this->validateRefreshAccess();

                $authenticate = App::make(\Helpers\Authenticate::class);
                $user = $authenticate->getUserByToken($validatedToken);

                if (!$authenticate->getRefreshCount($user) || $authenticate->getRefreshCount($user) === 0) {
                    $token = $this->createAccessToken($user);
                    $this->sendRefreshAccessToken($user);
                    $token = !empty($token) ? JWT::decode($token, $secret, ['HS256']) : null;
                    $authenticate->setRefreshCount($user, 1);
                    return $token;
                } else {
                    throw new \Exception(t('user had already an refresh'));
                }
            } catch (\Exception $e) {
                throw new \Exception(t('no valid refresh Token'));
            }
        } else {
            throw new \Exception(t('Expired Token'));
        }
    }
}
