<?php

namespace Helpers;

use Firebase\JWT\JWT;
use Concrete\Core\Support\Facade\Application as App;
use Concrete\Core\Error\UserMessageException;
use Concrete\Core\User\User;
use Concrete\Core\User\UserInfoRepository;
use Concrete\Core\Cookie\ResponseCookieJar;
use Concrete\Core\Support\Facade\Log;

class Token
{
    public function createAccessToken(User $user): ?string
    {
        $notBefore = $this->checkIfUserCanCreateToken($user);
        $token = $this->createToken($user, $notBefore, $this->getTokenExpiration());

        $authenticate = App::make(\Helpers\Authenticate::class);
        $authenticate->setTokenExpires($user, $token['exp']);

        JWT::$leeway = 60;
        $token       = JWT::encode($token, $this->getSecretKey());


        return !empty($token) ? $token : null;
    }

    public function sendRefreshAccessToken(User $user)
    {
        $refreshToken = $this->createRefreshToken($user);

        $config = App::make('config');
        $cookie_name = (string) $config->get('concrete5_graphql_websocket_security::graphql_jwt.cookie.cookie_name');
        $cookie_path = (string) $config->get('concrete5_graphql_websocket_security::graphql_jwt.cookie.cookie_path');
        $cookie_lifetime = (int)  time() + $config->get('concrete5_graphql_websocket_security::graphql_jwt.cookie.cookie_lifetime');
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

    public function validateRefreshAccess(): ?User
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

    private function createRefreshToken(User $user): ?string
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

    public function validateToken(string $token, bool $isRefresh = false): ?User
    {
        $authenticate = App::make(\Helpers\Authenticate::class);
        $user = null;

        if (empty($token)) {
            Log::addInfo(t('No JWT provided'));
            return false;
        }

        $secret = '';
        if (!$isRefresh) {
            $secret = $this->getSecretKey();
        } else {
            $secret = $this->getRefreshSecretKey();
        }

        if (!$secret) {
            Log::addInfo(t('JWT is not configured properly'));
            throw new UserMessageException(t('JWT is not configured properly'));
        }

        try {
            JWT::$leeway = 60;

            $token = !empty($token) ? JWT::decode($token, $secret, ['HS256']) : null;

            $baseUrl = sprintf(
                "%s://%s",
                $this->isSecure() ? 'https' : 'http',
                $_SERVER['SERVER_NAME']
            );
            // websocketserver has no server_name
            if (isset($_SERVER['SERVER_NAME']) && $baseUrl !== $token->iss) {
                Log::addInfo(t('The iss do not match with this server'));
                throw new \Exception(t('The iss do not match with this server'));
            }

            $user = $authenticate->getUserByToken($token);

            if (!isset($token->data->user->user_secret) || $this->getUserJwtSecret($user) !== $token->data->user->user_secret) {
                Log::addInfo(t('The User Secret does not match or has been revoked for this user'));
                throw new \Exception(t('The User Secret does not match or has been revoked for this user'));
            }
        } catch (\Exception $error) {
            if ($error->getMessage() === 'Expired token') {
                Log::addInfo(t('Expired token'));
                throw new UserMessageException(t('Expired token'), 401);
            } else {
                Log::addInfo(t('The JWT Token is invalid'));
                throw new UserMessageException(t('The JWT Token is invalid'), 401);
            }
        }

        return $user;
    }

    private function checkIfUserCanCreateToken(User $user): int
    {
        $notBefore = $this->getNotBefore($user);

        if ($this->isJwtSecretRevoked($user)) {
            Log::addInfo(t('The JWT token cannot be issued for this user'));
            throw new \Exception(t('The JWT token cannot be issued for this user'));
        }

        return (int) $notBefore;
    }

    private function isSecure(): bool {
        return
          (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
          || $_SERVER['SERVER_PORT'] == 443;
      }

    private function createToken(User $user, int $notBefore, int $expiration)
    {
        $baseUrl = sprintf(
            "%s://%s",
            $this->isSecure() ? 'https' : 'http',
            $_SERVER['SERVER_NAME']
        );

        //https://tools.ietf.org/html/rfc7519#section-4.1

        $returnUser = [];
        if ($user) {
            $userInfo = App::make(UserInfoRepository::class)->getByID((int) $user->getUserID());
            $uo = $userInfo->getUserObject();
            $returnUser = [
                "uID" => $user->getUserID(),
                "uName" => $user->getUserName(),
                "uEmail" => $userInfo->getUserEmail(),
                "uDefaultLanguage" => $userInfo->getUserDefaultLanguage(),
                "uIsValidated" => $userInfo->isValidated(),
                "uAvatar" => $userInfo->getUserAvatar()->getPath(),
                "uGroupsPath" => is_array($uo->getUserGroupObjects()) ? array_map(function ($item) {
                    return $item->getGroupPath();
                }, $uo->getUserGroupObjects()) : [],
            ];
        }

        $token = [
            'iss'  => $baseUrl,
            'iat'  => time(),
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

    private function getNotBefore(User $user): int
    {
        $authenticate = App::make(\Helpers\Authenticate::class);
        $notBefore = $authenticate->getNotBefore($user);

        return (int) $notBefore > 0 ? $notBefore : time();
    }

    /**
     * Returns the expiration for the token
     *
     * @return mixed|string|null
     */
    private function getTokenExpiration(): int
    {
        $config = App::make('config');
        $expirationConfig = (int) $config->get('concrete5_graphql_websocket_security::graphql_jwt.auth_expire');

        if ($expirationConfig > 0) {
            return (int) time() + $expirationConfig;
        } else {
            return (int) time() + 30;
        }
    }

    /**
     * Returns the expiration for the refresh token
     *
     * @return mixed|string|null
     */
    private function getRefreshTokenExpiration(): int
    {
        $config = App::make('config');
        $expirationConfig = (int) $config->get('concrete5_graphql_websocket_security::graphql_jwt.auth_refresh_expire');

        if ($expirationConfig > 0) {
            return (int) time() + $expirationConfig;
        } else {
            return (int) time() + (86400 * 365);
        }
    }

    /**
     * Given a User ID, returns the user's JWT secret
     *
     * @param User $user
     *
     * @return mixed|string
     */
    private function getUserJwtSecret(User $user): string
    {
        $authenticate = App::make(\Helpers\Authenticate::class);

        if (true === $this->isJwtSecretRevoked($user)) {
            if (!empty($currentUser)) {
                Log::addInfo(t('The JWT Auth secret cannot be returned'));
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
        return (string) $secret;
    }

    /**
     * Given a User, returns whether their JWT secret has been revoked or not.
     *
     * @param User $user
     *
     * @return bool
     */
    private function isJwtSecretRevoked(User $user):bool
    {
        $authenticate = App::make(\Helpers\Authenticate::class);
        return $authenticate->getRevoked($user) ?? false;
    }

    /**
     * Given a User ID, issue a new JWT Auth Secret
     *
     * @param User $user The user the secret is being issued for
     *
     * @return string $secret The JWT User secret for the user.
     */
    private function issueNewUserSecret(User $user)
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
    private function getSecretKey(): string
    {
        $config = App::make('config');
        $secret_key = (string) $config->get('concrete5_graphql_websocket_security::graphql_jwt.auth_secret_key');


        if (empty($secret_key)) {
            Log::addInfo(t('JWT Auth is not configured correctly. Please contact a site administrator.'));
            throw new UserMessageException(t('JWT Auth is not configured correctly. Please contact a site administrator.'));
        }
        return (string) $secret_key;
    }

    /**
     * This returns the secret key, using the defined constant if defined, and passing it through a filter to
     * allow for the config to be able to be set via another method other than a defined constant, such as an
     * admin UI that allows the key to be updated/changed/revoked at any time without touching server files
     *
     * @return mixed|null|string
     * @since 0.0.1
     */
    private function getRefreshSecretKey(): string
    {
        $config = App::make('config');
        $secret_key = (string) $config->get('concrete5_graphql_websocket_security::graphql_jwt.auth_refresh_secret_key');

        if (empty($secret_key)) {
            Log::addInfo(t('JWT Auth is not configured correctly. Please contact a site administrator.'));
            throw new UserMessageException(t('JWT Auth is not configured correctly. Please contact a site administrator.'));
        }
        return (string) $secret_key;
    }
}
