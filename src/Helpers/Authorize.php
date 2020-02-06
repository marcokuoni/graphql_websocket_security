<?php

namespace Helpers;

use Concrete\Core\Support\Facade\Application as App;
use Symfony\Component\HttpFoundation\JsonResponse;
use Concrete\Core\Error\UserMessageException;

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
        try {
            $authenticate = App::make(\Helpers\Authenticate::class);
            $user = $authenticate->authenticateUser($username, $password);

            $token = App::make(\Helpers\Token::class);
            $accessToken = $token->createAccessToken($user);
            $token->sendRefreshAccessToken($user);
        } catch (\Exception $e) {
            return ['error' => $e->getMessage(), 'authToken' => ''];
        }

        return ['error' => '', 'authToken' => $accessToken];
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
