<?php

namespace Helpers;

defined('C5_EXECUTE') or die('Access Denied.');

use Concrete\Core\Controller\Controller;
use Siler\Http\Request;
use Siler\GraphQL as SilerGraphQL;
use Siler\Http\Response;
use Concrete\Core\Support\Facade\Application as App;
use Doctrine\ORM\EntityManagerInterface;
use Entity\AnonymusUser as AnonymusUserEntity;
use Concrete\Core\Localization\Localization;
use Concrete\Core\Http\Request as ConcreteRequest;
use Concrete\Core\Permission\IPService;

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

            $config = App::make('config');
            if ((bool) $config->get('concrete5_graphql_websocket_security::graphql_jwt.log_requests')) {
                $ipService = App::make(IPService::class);
                $request = App::make(ConcreteRequest::class);
                $ip = (string) $ipService->getRequestIPAddress();
                $timezone = date_default_timezone_get();
                $language = Localization::activeLocale();
                $currentTime = time();
                $userAgent = $request->server->get('HTTP_USER_AGENT');

                if (method_exists($user, 'getAnonymus') && $user->getAnonymus()) {
                    if ((bool) $config->get('concrete5_graphql_websocket_security::graphql_jwt.log_anonymus_users')) {
                        $entityManager = App::make(EntityManagerInterface::class);
                        $anonymusUserRepository = $entityManager->getRepository(AnonymusUserEntity::class);

                        $item = $anonymusUserRepository->findOneBy(['uID' => $user->getUserID()]);

                        $item->setUserGraphqlJwtLastRequest($currentTime);
                        $item->setUserGraphqlJwtLastRequestIp($ip);
                        $item->setUserGraphqlJwtLastRequestAgent($userAgent);
                        $item->setUserGraphqlJwtLastRequestTimezone($timezone);
                        $item->setUserGraphqlJwtLastRequestLanguage($language);
                        $item->setUserGraphqlJwtRequestCount($item->getUserGraphqlJwtRequestCount() > 0 ? ($item->getUserGraphqlJwtRequestCount() + 1) : 1);
                        $entityManager->persist($item);
                        $entityManager->flush();
                    }
                } else {
                    $userInfo = $user->getUserInfoObject();
                    $userInfo->setAttribute("graphql_jwt_last_request", $currentTime);
                    $userInfo->setAttribute("graphql_jwt_last_request_ip", $ip);
                    $userInfo->setAttribute("graphql_jwt_last_request_agent", $userAgent);
                    $userInfo->setAttribute("graphql_jwt_last_request_timezone", $timezone);
                    $userInfo->setAttribute("graphql_jwt_last_request_language", $language);
                    $userInfo->setAttribute("graphql_jwt_request_count", $userInfo->getAttributeValue("graphql_jwt_request_count") > 0 ? ($userInfo->getAttributeValue("graphql_jwt_request_count") + 1) : 1);
                }
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
