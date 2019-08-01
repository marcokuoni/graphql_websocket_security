<?php

namespace Helpers;

defined('C5_EXECUTE') or die('Access Denied.');

use Concrete\Core\Controller\Controller;
use Siler\Http\Request;
use Siler\GraphQL as SilerGraphQL;
use Siler\Http\Response;
use Concrete\Core\Support\Facade\Application as App;

class Api extends Controller
{
    public function view()
    {
        Response\header('Access-Control-Expose-Headers', 'X-JWT-Refresh');
        Response\header('Access-Control-Allow-Origin', '*');
        Response\header('Access-Control-Allow-Headers', 'content-type');

        $authorize = App::make(\Helpers\Authorize::class);
        $validateRefreshHeader = $authorize->validateToken($authorize->getRefreshHeader(), true);

        if (!empty($validateRefreshHeader->data->user->uID)) {
            $user = $authorize->authenticated($validateRefreshHeader);
            $authToken = $authorize->getToken($user, false);

            if (!empty($authToken)) {
                Response\header('X-JWT-Auth', $authToken);
            }
        }

        $validateAuthHeader = $authorize->validateToken(null, false);

        if (!empty($validateAuthHeader->data->user->uID)) {
            $user = $authorize->authenticated($validateAuthHeader);
            $refreshToken = $authorize->getRefreshToken($user, false);

            if (!empty($refreshToken)) {
                Response\header('X-JWT-Refresh', $refreshToken);
            }

            $authenticate = App::make(\Helpers\Authenticate::class);
            $authenticate->logRequest($user);
        } else {
            if (Request\header('Content-Type') == 'application/json') {
                $data = Request\json('php://input');
            } else {
                $data = Request\post();
            }

            if (!is_array($data)) {
                throw new \UnexpectedValueException('Input should be a JSON object');
            }

            $config = App::make('config');
            if ((bool) $config->get('concrete5_graphql_websocket_security::graphql_jwt.just_with_valid_token')) {
                throw new \Exception(t('You need to provide a proven token'));
            }
        }

        if (Request\method_is('post')) {
            $schema = \Concrete5GraphqlWebsocket\SchemaBuilder::get();
            SilerGraphQL\init($schema);
        }
    }
}
