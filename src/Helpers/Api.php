<?php

namespace Helpers;

defined('C5_EXECUTE') or die('Access Denied.');

use Concrete\Core\Controller\Controller;
use Siler\GraphQL as SilerGraphQL;
use Siler\Http\Request;
use Siler\Http\Response;
use Concrete\Core\Support\Facade\Application as App;
use Concrete\Core\User\User;

class Api extends Controller
{
    public function view()
    {

        /**
         * If there's a Refresh-Authorization token in the request headers, validate it
         */
        $auth = App::make(\Helpers\Auth::class);
        $validateRefreshHeader = $auth->validateToken($auth->getRefreshHeader(), true);

        /**
         * If the refresh token in the request headers is valid, return a JWT Auth token that can be used for future requests
         */
        if (!empty($validateRefreshHeader->data->user->id)) {

            /**
             * Get an auth token and refresh token to return
             */
            $user = User::getByUserID($validateRefreshHeader->data->user->id);
            $authToken = $auth->getToken($user, false);

            /**
             * If the tokens can be generated (not revoked, etc), return them
             */
            if (!empty($authToken)) {
                Response\header('X-JWT-Auth', $authToken);
            }
        }

        $validateAuthHeader = $auth->validateToken(null, false);

        if (!empty($validateAuthHeader->data->user->id)) {

            $user = User::getByUserID($validateAuthHeader->data->user->id);
            $refreshToken = $auth->getRefreshToken($user, false);

            if (!empty($refreshToken)) {
                Response\header('X-JWT-Refresh', $refreshToken);
            }
        }

        Response\header('Access-Control-Expose-Headers', 'X-JWT-Refresh');
        Response\header('Access-Control-Allow-Origin', '*');
        Response\header('Access-Control-Allow-Headers', 'content-type');

        if (Request\method_is('post')) {
            $schema = \Concrete5GraphqlWebsocket\SchemaBuilder::get();
            SilerGraphQL\init($schema);
        }
    }
}
