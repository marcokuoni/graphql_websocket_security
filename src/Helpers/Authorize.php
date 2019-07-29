<?php

namespace Helpers;

use Firebase\JWT\JWT;
use GraphQL\Error\UserError;
use Concrete\Core\Support\Facade\Application as App;
use Concrete\Core\User\User;
use Concrete\Core\User\UserInfo;
use Permissions;

class Authorize
{
    protected $issued;
    protected $expiration;
    protected $isRefreshToken = false;

    /**
     * This returns the secret key, using the defined constant if defined, and passing it through a filter to
     * allow for the config to be able to be set via another method other than a defined constant, such as an
     * admin UI that allows the key to be updated/changed/revoked at any time without touching server files
     *
     * @return mixed|null|string
     * @since 0.0.1
     */
    public function getSecretKey()
    {
        $config = App::make('config');
        $secret_key = (string) $config->get('concrete5_graphql_websocket_security::graphql_jwt.auth_secret_key');
        return $secret_key;
    }

    /**
     * Get the user and password in the request body and generate a JWT
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
        if (empty($this->getSecretKey())) {
            throw new UserError(t('JWT Auth is not configured correctly. Please contact a site administrator.'));
        }

        $authenticate = App::make(\Helpers\Authenticate::class);
        $user = $authenticate->authenticateUser($username, $password, $anonymus);

        $response = [
            'authToken'    => $this->getSignedToken($user),
            'refreshToken' => $this->getRefreshToken($user),
            'user'         => json_decode(json_encode($user)),
        ];

        return !empty($response) ? $response : [];
    }

    public function loginAndGetTokenFromAnonymus()
    {
        if (empty($this->getSecretKey())) {
            throw new UserError(t('JWT Auth is not configured correctly. Please contact a site administrator.'));
        }

        $authenticate = App::make(\Helpers\Authenticate::class);
        $user = $authenticate->authenticateAnonymus();

        $response = [
            'authToken'    => $this->getSignedToken($user),
            'refreshToken' => $this->getRefreshToken($user),
            'user'         => json_decode(json_encode($user)),
        ];

        return !empty($response) ? $response : [];
    }

    public function logout()
    {
        $authenticate = App::make(\Helpers\Authenticate::class);
        return $authenticate->deauthenticateUser($this->authenticated());
    }

    public function authenticated($token = null)
    {
        if (empty($token)) {
            $token = $this->validateToken(null, false);
        }
        if ($token) {
            if ($token->data->user->anonymus) {
                $authenticate = App::make(\Helpers\Authenticate::class);
                return $authenticate->getAnonymusUser($token->data->user->uID);
            } else {
                return User::getByUserID($token->data->user->uID);
            }
        }
        throw new \Exception(t('Unauthenticated!'));
        return false;
    }

    /**
     * Get the issued time for the token
     *
     * @return int
     */
    public function getTokenIssued()
    {
        if (!isset($this->issued)) {
            $this->issued = time();
        }

        return $this->issued;
    }

    /**
     * Returns the expiration for the token
     *
     * @return mixed|string|null
     */
    public function getTokenExpiration()
    {

        if (!isset($this->expiration)) {
            $config = App::make('config');
            $expirationConfig = (int) $config->get('concrete5_graphql_websocket_security::graphql_jwt.auth_expire');
            if ($expirationConfig > 0) {
                $this->expiration = $this->getTokenIssued() + $expirationConfig;
            } else {
                $this->expiration = $this->getTokenIssued() + 300;
            }
        }

        return !empty($this->expiration) ? $this->expiration : null;
    }

    /**
     * Given a User ID, returns the user's JWT secret
     *
     * @param User $user
     *
     * @return mixed|string
     */
    public function getUserJwtSecret($user)
    {
        if (true === $this->isJwtSecretRevoked($user)) {
            throw new \Exception(t('The JWT Auth secret cannot be returned'));
        }

        $currentUser = App::make(User::class);
        $isCurrentUser = ((int) $user->getUserID() === (int) $currentUser->getUserID()) ? true : false;

        if (method_exists($user, 'getAnonymus') && $user->getAnonymus()) {
            if (!$isCurrentUser) {
                throw new \Exception(t('The JWT Auth secret for this user cannot be returned'));
            }
        } else {
            $up = new Permissions(UserInfo::getByID((int) $currentUser->getUserID()));
            if (!$isCurrentUser || !$up->canEditUser()) {
                throw new \Exception(t('The JWT Auth secret for this user cannot be returned'));
            }
        }

        //TODO: get user attribute
        //$secret = get_user_meta($userId, 'graphql_jwt_auth_secret', true);

        if (empty($secret) || !is_string($secret)) {
            $secret = $this->issueNewUserSecret($user);
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
     * Given a User ID, issue a new JWT Auth Secret
     *
     * @param User $user The user the secret is being issued for
     *
     * @return string $secret The JWT User secret for the user.
     */
    public function issueNewUserSecret($user)
    {
        $secret = null;

        if (!$this->isJwtSecretRevoked($user)) {
            $secret = uniqid('graphql_jwt_');
            //TODO: set user attribute
            //update_user_meta($userId, 'graphql_jwt_auth_secret', $secret);
        }

        return $secret ? $secret : null;
    }

    /**
     * Given a User, returns whether their JWT secret has been revoked or not.
     *
     * @param User $user
     *
     * @return bool
     */
    public function isJwtSecretRevoked($user)
    {
        //TODO: get user attribute graphql_jwt_auth_secret_revoked
        //$revoked = (bool) get_user_meta($userId, 'graphql_jwt_auth_secret_revoked', true);
        $revoked = null;

        return isset($revoked) && true === $revoked ? true : false;
    }

    /**
     * Public method for getting an Auth token for a given user
     *
     * @param \WP_USer $user The user to get the token for
     *
     * @return null|string
     */
    public function getToken($user, $cap_check = true)
    {
        return $this->getSignedToken($user, $cap_check);
    }

    public function getRefreshToken($user, $cap_check = true)
    {
        $this->isRefreshToken = true;

        return $this->getSignedToken($user, $cap_check);
    }

    public function isRefreshToken()
    {
        return true === $this->isRefreshToken ? true : false;
    }

    /**
     * Given a user ID, if the ID is for a valid user and the current user has proper capabilities, this revokes
     * the JWT Secret from the user.
     *
     * @param User $user
     *
     * @return mixed|boolean|\Exception
     */
    public function revokeUserSecret($user)
    {
        $currentUser = App::make(User::class);

        if (method_exists($user, 'getAnonymus') && $user->getAnonymus()) {
            if (0 !== $user->getUserID() && $user->getUserID() === $currentUser->getUserID()) {
                //TODO: Set user attribute
                //update_user_meta($userId, 'graphql_jwt_auth_secret_revoked', 1);

                return true;
            } else {
                throw new \Exception(t('The JWT Auth Secret cannot be revoked for this user'));
            }
        } else {
            $up = new Permissions(UserInfo::getByID($user->getUserID()));
            if (0 !== $user->getUserID() && ($up->canEditUser() ||
                $user->getUserID() === $currentUser->getUserID())) {
                //TODO: Set user attribute
                //update_user_meta($userId, 'graphql_jwt_auth_secret_revoked', 1);

                return true;
            } else {
                throw new \Exception(t('The JWT Auth Secret cannot be revoked for this user'));
            }
        }
    }

    /**
     * Given a user ID, if the ID is for a valid user and the current user has proper capabilities, this unrevokes
     * the JWT Secret from the user.
     *
     * @param User $user
     *
     * @return mixed|boolean|\Exception
     */
    public function unrevokeUserSecret($user)
    {
        if (method_exists($user, 'getAnonymus') && $user->getAnonymus()) {
            $up = new Permissions(UserInfo::getByID($user->getUserID()));
            if (0 !== $user->getUserID()) {
                //TODO: set user attribute
                //update_user_meta($userId, 'graphql_jwt_auth_secret_revoked', 0);
                $this->issueNewUserSecret($user);

                return true;
            } else {
                throw new \Exception(t('The JWT Auth Secret cannot be unrevoked for this user'));
            }
        } else {
            $up = new Permissions(UserInfo::getByID($user->getUserID()));
            if (0 !== $user->getUserID() && $up->canEditUser()) {
                //TODO: set user attribute
                //update_user_meta($userId, 'graphql_jwt_auth_secret_revoked', 0);
                $this->issueNewUserSecret($user);

                return true;
            } else {
                throw new \Exception(t('The JWT Auth Secret cannot be unrevoked for this user'));
            }
        }
    }

    /**
     * Main validation function, this function try to get the Authentication
     * headers and decoded.
     *
     * @param string $token The encoded JWT Token
     *
     * @throws \Exception
     * @return mixed|boolean|string
     */
    public function validateToken($token = null, $refresh = false)
    {

        $this->isRefreshToken = (true === $refresh) ? true : false;

        if (empty($token)) {
            $authHeader = $this->getAuthHeader();

            if (empty($authHeader)) {
                return false;
            } else {
                list($token) = sscanf($authHeader, 'Bearer %s');
            }
        }

        if (!$this->getSecretKey()) {
            throw new \Exception(t('JWT is not configured properly'));
        }

        try {
            JWT::$leeway = 60;

            $secret = $this->getSecretKey();
            $token = !empty($token) ? JWT::decode($token, $secret, ['HS256']) : null;

            $baseUrl = sprintf(
                "%s://%s",
                isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] != 'off' ? 'https' : 'http',
                $_SERVER['SERVER_NAME']
            );
            if ($baseUrl !== $token->iss) {
                throw new \Exception(t('The iss do not match with this server'));
            }

            if (!isset($token->data->user->uID)) {
                throw new \Exception(t('User ID not found in the token'));
            }

            if (isset($token->data->user->user_secret)) {
                if ($token->data->user->anonymus) {
                    $user = \Helpers\User();
                } else {
                    $user = User::getByUserID($token->data->user->uID);
                }
                if ($this->getUserJwtSecret($user) !== $token->data->user->user_secret) {
                    throw new \Exception(t('The User Secret does not match or has been revoked for this user'));
                }
            }
        } catch (\Exception $error) {
            throw new \Exception(t('The JWT Token is invalid'));
        }

        $this->isRefreshToken = false;

        return $token;
    }

    /**
     * Get the value of the Authorization header from the $_SERVER super global
     *
     * @return mixed|string
     */
    public function getAuthHeader()
    {
        $authHeader = isset($_SERVER['HTTP_AUTHORIZATION']) ? $_SERVER['HTTP_AUTHORIZATION'] : false;
        $redirectAuthHeader = isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION']) ? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] : false;
        $authHeader = $authHeader !== false ? $authHeader : ($redirectAuthHeader !== false ? $redirectAuthHeader : null);

        return $authHeader;
    }

    public function getRefreshHeader()
    {
        $refreshHeader = isset($_SERVER['HTTP_REFRESH_AUTHORIZATION']) ? sanitize_text_field($_SERVER['HTTP_REFRESH_AUTHORIZATION']) : false;

        return $refreshHeader;
    }

    /**
     * @param $user
     *
     * @return null|string
     */
    protected function getSignedToken($user, $capCheck = true)
    {
        $currentUser = App::make(User::class);
        if (true === $capCheck && $currentUser->getUserID() !== $user->getUserID() || 0 === $user->getUserID()) {
            throw new \Exception(t('Only the user requesting a token can get a token issued for them'));
        }

        $notBefore = $this->getTokenIssued(); //TODO: set from user or use issued as default: $user->authNotBefore($this->getTokenIssued());

        $baseUrl = sprintf(
            "%s://%s",
            isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] != 'off' ? 'https' : 'http',
            $_SERVER['SERVER_NAME']
        );

        //https://tools.ietf.org/html/rfc7519#section-4.1
        $token = [
            'iss'  => $baseUrl,
            'iat'  => $this->getTokenIssued(),
            'nbf'  => $notBefore,
            'exp'  => self::getTokenExpiration(),
            'data' => [
                'user' => json_decode(json_encode($user))
            ],
        ];


        $secret = $this->getUserJwtSecret($user);
        if (!empty($secret) && true === $this->isRefreshToken()) {
            /**
             * Set the expiration date as a year from now to make the refresh token long lived, allowing the
             * token to be valid without changing as long as it has not been revoked or otherwise invalidated,
             * such as a refreshed user secret.
             */
            $token['exp']                         = $this->getTokenIssued() + (86400 * 365);
            $token['data']['user']->{'user_secret'} = $secret;

            $this->isRefreshToken = false;
        }

        JWT::$leeway = 60;
        $token       = JWT::encode($token, $this->getSecretKey());

        if ($this->isJwtSecretRevoked($user)) {
            throw new \Exception(t('The JWT token cannot be issued for this user'));
        }

        return !empty($token) ? $token : null;
    }
}
