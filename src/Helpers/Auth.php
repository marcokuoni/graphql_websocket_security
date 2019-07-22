<?php

namespace Helpers;

use Firebase\JWT\JWT;
use GraphQL\Error\UserError;
use Concrete\Core\Support\Facade\Application as App;
use Concrete\Core\User\Login\LoginService;
use Concrete\Core\User\Exception\FailedLoginThresholdExceededException;
use Concrete\Core\User\Exception\UserDeactivatedException;
use Concrete\Core\User\Exception\UserException;
use Concrete\Core\User\Exception\UserPasswordResetException;
use Concrete\Core\User\User;
use Concrete\Core\Error\UserMessageException;
use Core;
use Session;
use Exception;
use Permissions;
use UserInfo;

class Auth
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

        // Use the defined secret key, if it exists
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
        /**
         * First thing, check the secret key if not exist return a error
         */
        if (empty($this->getSecretKey())) {
            throw new UserError(t('JWT Auth is not configured correctly. Please contact a site administrator.'));
        }

        /**
         * Authenticate the user and get the Authenticated user object in response
         */
        $user = $this->authenticateUser($username, $password);

        /**
         * The token is signed, now create the object with basic user data to send to the client
         */
        $response = [
            'authToken'    => $this->getSignedToken($user),
            'refreshToken' => $this->getRefreshToken($user),
            'user'         => json_decode(json_encode($user)),
        ];

        /**
         * Let the user modify the data before send it back
         */
        return !empty($response) ? $response : [];
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

            /**
             * Set the expiration time, default is 300 seconds.
             */
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
     * @param int $userId
     *
     * @return mixed|string
     */
    public function getUserJwtSecret($userId)
    {

        /**
         * If the secret has been revoked, throw an error
         */
        if (true === $this->isJwtSecretRevoked($userId)) {
            throw new \Exception(t('The JWT Auth secret cannot be returned'));
        }

        /**
         * If the request is not from the current_user or the current_user doesn't have the proper capabilities, don't return the secret
         */
        $currentUser = App::make(User::class);
        $isCurrentUser = ($userId === $currentUser->getUserID()) ? true : false;

        $up = new Permissions(UserInfo::getByID($currentUser->getUserID()));
        if (!$isCurrentUser || !$up->canEditUser()) {
            throw new \Exception(t('The JWT Auth secret for this user cannot be returned'));
        }

        /**
         * Get the stored secret
         */
        //TODO: get user attribute
        //$secret = get_user_meta($userId, 'graphql_jwt_auth_secret', true);

        /**
         * If there is no stored secret, or it's not a string
         */
        if (empty($secret) || !is_string($secret)) {
            $secret = $this->issueNewUserSecret($userId);
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
     * @param int $userId The ID of the user the secret is being issued for
     *
     * @return string $secret The JWT User secret for the user.
     */
    public function issueNewUserSecret($userId)
    {

        /**
         * Get the current user secret
         */
        $secret = null;

        /**
         * If the JWT Secret is not revoked for the user, generate a new one
         */
        if (!$this->isJwtSecretRevoked($userId)) {

            /**
             * Generate a new one and store it
             */
            $secret = uniqid('graphql_jwt_');
            //TODO: set user attribute
            //update_user_meta($userId, 'graphql_jwt_auth_secret', $secret);
        }

        return $secret ? $secret : null;
    }

    /**
     * Given a User, returns whether their JWT secret has been revoked or not.
     *
     * @param int $userId
     *
     * @return bool
     */
    public function isJwtSecretRevoked($userId)
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
    public function getToken(User $user, $cap_check = true)
    {
        return $this->getSignedToken($user, $cap_check);
    }

    public function getRefreshToken(User $user, $cap_check = true)
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
     * @param int $userId
     *
     * @return mixed|boolean|\Exception
     */
    public function revokeUserSecret(int $userId)
    {
        /**
         * If the current user can edit users, or the current user is the user being edited
         */
        $user = User::getByUserID($userId);
        $currentUser = App::make(User::class);
        $up = new Permissions(UserInfo::getByID($user->getUserID()));
        if (0 !== $user->getUserID() && ($up->canEditUser() ||
            $user->getUserID() === $currentUser->getUserID())) {
            /**
             * Set the user meta as true, marking the secret as revoked
             */
            //TODO: Set user attribute
            //update_user_meta($userId, 'graphql_jwt_auth_secret_revoked', 1);

            return true;
        } else {
            throw new \Exception(t('The JWT Auth Secret cannot be revoked for this user'));
        }
    }

    /**
     * Given a user ID, if the ID is for a valid user and the current user has proper capabilities, this unrevokes
     * the JWT Secret from the user.
     *
     * @param int $userId
     *
     * @return mixed|boolean|\Exception
     */
    public function unrevokeUserSecret(int $userId)
    {

        /**
         * If the user_id is a valid user, and the current user can edit_users
         */
        $user = User::getByUserID($userId);
        $up = new Permissions(UserInfo::getByID($user->getUserID()));
        if (0 !== $user->getUserID() && $up->canEditUser()) {

            /**
             * Issue a new user secret, invalidating any that may have previously been in place, and mark the
             * revoked meta key as false, showing that the secret has not been revoked
             */
            $this->issueNewUserSecret($userId);
            //TODO: set user attribute
            //update_user_meta($userId, 'graphql_jwt_auth_secret_revoked', 0);

            return true;
        } else {
            throw new \Exception(t('The JWT Auth Secret cannot be unrevoked for this user'));
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

        /**
         * If a token isn't passed to the method, check the Authorization Headers to see if a token was
         * passed in the headers
         *
         * @since 0.0.1
         */
        if (empty($token)) {

            /**
             * Get the Auth header
             */
            $authHeader = $this->getAuthHeader();

            /**
             * If there's no $auth, return an error
             *
             * @since 0.0.1
             */
            if (empty($authHeader)) {
                return false;
            } else {
                /**
                 * The HTTP_AUTHORIZATION is present verify the format
                 * if the format is wrong return the user.
                 */
                list($token) = sscanf($authHeader, 'Bearer %s');
            }
        }

        /**
         * If there's no secret key, throw an error as there needs to be a secret key for Auth to work properly
         */
        if (!$this->getSecretKey()) {
            throw new \Exception(t('JWT is not configured properly'));
        }

        /**
         * Try to decode the token
         */
        try {

            /**
             * Decode the Token
             */
            JWT::$leeway = 60;

            $secret = $this->getSecretKey();
            $token = !empty($token) ? JWT::decode($token, $secret, ['HS256']) : null;

            /**
             * The Token is decoded now validate the iss
             */
            if (get_bloginfo('url') !== $token->iss) {
                throw new \Exception(t('The iss do not match with this server'));
            }

            /**
             * So far so good, validate the user id in the token
             */
            if (!isset($token->data->user->id)) {
                throw new \Exception(t('User ID not found in the token'));
            }

            /**
             * If there is a user_secret in the token (refresh tokens) make sure it matches what
             */
            if (isset($token->data->user->user_secret)) {
                if ($this->isJwtSecretRevoked($token->data->user->id)) {
                    throw new \Exception(t('The User Secret does not match or has been revoked for this user'));
                }
            }

            /**
             * If any exceptions are caught
             */
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
        /**
         * Looking for the HTTP_AUTHORIZATION header, if not present just
         * return the user.
         */
        $authHeader = isset($_SERVER['HTTP_AUTHORIZATION']) ? $_SERVER['HTTP_AUTHORIZATION'] : false;

        /**
         * Double check for different auth header string (server dependent)
         */
        $redirectAuthHeader = isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION']) ? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] : false;

        /**
         * If the $auth header is set, use it. Otherwise attempt to use the $redirect_auth header
         */
        $authHeader = $authHeader !== false ? $authHeader : ($redirectAuthHeader !== false ? $redirectAuthHeader : null);

        /**
         * Return the auth header, pass through a filter
         *
         * @param string $authHeader The header used to authenticate a user's HTTP request
         */
        return $authHeader;
    }

    public function getRefreshHeader()
    {
        /**
         * Check to see if the incoming request has a "Refresh-Authorization" header
         */
        $refreshHeader = isset($_SERVER['HTTP_REFRESH_AUTHORIZATION']) ? sanitize_text_field($_SERVER['HTTP_REFRESH_AUTHORIZATION']) : false;

        return $refreshHeader;
    }

    /**
     * Takes a username and password and authenticates the user and returns the authenticated user object
     *
     * @param string $username The username for the user to login
     * @param string $password The password for the user to login
     *
     * @return null|\Exception|User
     */
    protected function authenticateUser($username, $password)
    {
        /** @var \Concrete\Core\Permission\IPService $ip_service */
        $ip_service = Core::make('ip');
        if ($ip_service->isBlacklisted()) {
            throw new \Exception($ip_service->getErrorMessage());
        }

        /**
         * Try to authenticate the user with the passed credentials
         */
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

    protected function handleFailedLogin(LoginService $loginService, $username, $password, UserException $e)
    {
        if ($e instanceof InvalidCredentialsException) {
            // Track the failed login
            try {
                $loginService->failLogin($username, $password);
            } catch (FailedLoginThresholdExceededException $e) {
                $loginService->logLoginAttempt($username, ['Failed Login Threshold Exceeded', $e->getMessage()]);

                // Rethrow the failed threshold error
                throw $e;
            } catch (UserDeactivatedException $e) {
                $loginService->logLoginAttempt($username, ['User Deactivated', $e->getMessage()]);

                // Rethrow the user deactivated exception
                throw $e;
            }
        }

        $loginService->logLoginAttempt($username, ['Invalid Credentials', $e->getMessage()]);

        // Rethrow the exception
        throw $e;
    }

    /**
     * @param $user
     *
     * @return null|string
     */
    protected function getSignedToken(User $user, $capCheck = true)
    {

        /**
         * Only allow the currently signed in user access to a JWT token
         */
        $currentUser = App::make(User::class);
        if (true === $capCheck && $currentUser->getUserID() !== $user->getUserID() || 0 === $user->getUserID()) {
            throw new \Exception(t('Only the user requesting a token can get a token issued for them'));
        }

        /**
         * Determine the "not before" value for use in the token
         *
         * @param string   $issued The timestamp of the authentication, used in the token
         */
        $notBefore = $this->getTokenIssued(); //TODO: $user->authNotBefore($this->getTokenIssued());


        /**
         * Configure the token array, which will be encoded
         */
        $baseUrl = sprintf(
            "%s://%s",
            isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] != 'off' ? 'https' : 'http',
            $_SERVER['SERVER_NAME']
        );

        $token = [
            'iss'  => $baseUrl,
            'iat'  => $this->getTokenIssued(),
            'nbf'  => $notBefore,
            'exp'  => self::getTokenExpiration(),
            'data' => [
                'user' => [
                    'id' => $user->getUserID(),
                ],
            ],
        ];


        $secret = $this->getUserJwtSecret($user->getUserID());
        if (!empty($secret) && true === $this->isRefreshToken()) {
            /**
             * Set the expiration date as a year from now to make the refresh token long lived, allowing the
             * token to be valid without changing as long as it has not been revoked or otherwise invalidated,
             * such as a refreshed user secret.
             */
            $token['exp']                         = $this->getTokenIssued() + (86400 * 365);
            $token['data']['user']['user_secret'] = $secret;

            $this->isRefreshToken = false;
        }

        /**
         * Encode the token
         */
        JWT::$leeway = 60;
        $token       = JWT::encode($token, $this->getSecretKey());

        /**
         * Return the token
         */
        return !empty($token) ? $token : null;
    }
}
