<?php

namespace Helpers;

defined('C5_EXECUTE') or die('Access Denied.');

use Concrete\Core\Controller\Controller;
use Siler\Http\Request;
use Siler\GraphQL as SilerGraphQL;
use Siler\Http\Response;
use Concrete\Core\Support\Facade\Application as App;
use Symfony\Component\HttpFoundation\JsonResponse;

class Api extends Controller
{
    public function view()
    {
        if (Request\method_is('post')) {
            Response\cors();

            $config = App::make('config');
            try {
                $user = null;

                if ((bool) $config->get('concrete5_graphql_websocket_security::graphql_jwt.just_with_valid_token')) {
                    $authorize = App::make(\Helpers\Authorize::class);
                    $user = $authorize->authenticated();
                }

                if ($user) {
                    $authenticate = App::make(\Helpers\Authenticate::class);
                    $authenticate->logRequest($user);
                }
            } catch (\Exception $e) {
                if ((bool) $config->get('concrete5_graphql_websocket_security::graphql_jwt.just_with_valid_token')) {
                    return new JsonResponse($e, 401);
                }
            }

            if (Request\header('Content-Type') == 'application/json') {
                $data = Request\json('php://input');
            } else {
                $data = Request\post();
            }

            if (!is_array($data)) {
                throw new \UnexpectedValueException('Input should be a JSON object');
            }

            $schema = \Concrete5GraphqlWebsocket\SchemaBuilder::get();
            SilerGraphQL\init($schema);
        }
    }
}
