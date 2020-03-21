<?php

namespace Helpers;

use Concrete\Core\Support\Facade\Application as App;
use Concrete\Core\Foundation\ConcreteObject;

class AnonymusUser extends ConcreteObject
{
    public function setSecret($secret)
    {
        $config = App::make('config');
        $config->save('concrete5_graphql_websocket_security::graphql_jwt.anonymus_secret', (string) $secret);
    }

    public function getSecret()
    {
        $config = App::make('config');
        return (string) $config->get('concrete5_graphql_websocket_security::graphql_jwt.anonymus_secret');
    }

    public function setRefreshCount($count)
    {
        $config = App::make('config');
        $config->save('concrete5_graphql_websocket_security::graphql_jwt.anonymus_refresh_count', (int) $count);
    }

    public function getRefreshCount()
    {
        $config = App::make('config');
        return (int) $config->get('concrete5_graphql_websocket_security::graphql_jwt.anonymus_refresh_count');
    }

    public function setRevoked($revoked)
    {
        $config = App::make('config');
        $config->save('concrete5_graphql_websocket_security::graphql_jwt.anonymus_revoked', (bool) $revoked);
    }

    public function getRevoked()
    {
        $config = App::make('config');
        return (bool) $config->get('concrete5_graphql_websocket_security::graphql_jwt.anonymus_revoked');
    }

    public function setTokenExpires($expires)
    {
        $config = App::make('config');
        $config->save('concrete5_graphql_websocket_security::graphql_jwt.anonymus_token_expires', (int) $expires);
    }

    public function setRefreshTokenExpires($expires)
    {
        $config = App::make('config');
        $config->save('concrete5_graphql_websocket_security::graphql_jwt.anonymus_refresh_token_expires', (int) $expires);
    }

    public function getNotBefore()
    {
        $config = App::make('config');
        return (int) $config->get('concrete5_graphql_websocket_security::graphql_jwt.anonymus_get_not_before');
    }

    public function setLastRequest($timestamp)
    {
        $config = App::make('config');
        $config->save('concrete5_graphql_websocket_security::graphql_jwt.anonymus_last_request', (int) $timestamp);
    }

    public function setLastRequestIp($ip)
    {
        $config = App::make('config');
        $config->save('concrete5_graphql_websocket_security::graphql_jwt.anonymus_last_request_ip', (string) $ip);
    }

    public function setLastRequestAgent($agent)
    {
        $config = App::make('config');
        $config->save('concrete5_graphql_websocket_security::graphql_jwt.anonymus_last_request_agent', (string) $agent);
    }

    public function setLastRequestTimezone($timezone)
    {
        $config = App::make('config');
        $config->save('concrete5_graphql_websocket_security::graphql_jwt.anonymus_last_request_timezone', (string) $timezone);
    }

    public function setLastRequestLanguage($language)
    {
        $config = App::make('config');
        $config->save('concrete5_graphql_websocket_security::graphql_jwt.anonymus_last_request_language', (string) $language);
    }

    public function setRequestCount($count)
    {
        $config = App::make('config');
        $config->save('concrete5_graphql_websocket_security::graphql_jwt.anonymus_request_count', (int) $count);
    }

    public function getRequestCount()
    {
        $config = App::make('config');
        return (int) $config->get('concrete5_graphql_websocket_security::graphql_jwt.anonymus_request_count');
    }
}
