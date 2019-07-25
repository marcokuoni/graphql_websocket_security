<?php

namespace Helpers;

defined('C5_EXECUTE') or die('Access Denied.');

use Concrete\Core\Controller\Controller;
use Siler\GraphQL as SilerGraphQL;
use Siler\Http\Request;
use Siler\Http\Response;
use Concrete\Core\Support\Facade\Application as App;
use Concrete\Core\User\User;
use Exception;

class Api extends Controller
{
    public function view()
    {
        Response\header('Access-Control-Expose-Headers', 'X-JWT-Refresh');
        Response\header('Access-Control-Allow-Origin', '*');
        Response\header('Access-Control-Allow-Headers', 'content-type');

        /**
         * If there's a Refresh-Authorization token in the request headers, validate it
         */
        $auth = App::make(\Helpers\Auth::class);
        $validateRefreshHeader = $auth->validateToken($auth->getRefreshHeader(), true);

        /**
         * If the refresh token in the request headers is valid, return a JWT Auth token that can be used for future requests
         */
        if (!empty($validateRefreshHeader->data->user->uID)) {

            /**
             * Get an auth token and refresh token to return
             */
            $user = User::getByUserID($validateRefreshHeader->data->user->uID);
            $authToken = $auth->getToken($user, false);

            /**
             * If the tokens can be generated (not revoked, etc), return them
             */
            if (!empty($authToken)) {
                Response\header('X-JWT-Auth', $authToken);
            }
        }

        $validateAuthHeader = $auth->validateToken(null, false);

        if (!empty($validateAuthHeader->data->user->uID)) {
            $user = User::getByUserID($validateAuthHeader->data->user->uID);
            $refreshToken = $auth->getRefreshToken($user, false);

            if (!empty($refreshToken)) {
                Response\header('X-JWT-Refresh', $refreshToken);
            }
        } else {
            if (Request\header('Content-Type') == 'application/json') {
                $data = Request\json('php://input');
            } else {
                $data = Request\post();
            }

            if (!is_array($data)) {
                throw new \UnexpectedValueException('Input should be a JSON object');
            }
            //! This is not secure enough cause its not an exclusive check. So for now always check the token on every request
            if (preg_match('/(mutation|login|username|password)/', $data['query']) === 0) {
                throw new \Exception(t('You need first to login or provide a proven token'));
            }
        }

        if (Request\method_is('post')) {
            $schema = \Concrete5GraphqlWebsocket\SchemaBuilder::get();
            SilerGraphQL\init($schema);
        }
    }
}
