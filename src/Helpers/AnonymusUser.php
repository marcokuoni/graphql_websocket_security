<?php

namespace Helpers;

use Concrete\Core\Support\Facade\Application as App;
use Concrete\Core\Foundation\ConcreteObject;

class AnonymusUser extends ConcreteObject
{
    public function reset()
    {
        $config = App::make('config');

        $config->save('concrete5_graphql_websocket_security::graphql_jwt.anonymus_secret', (String) '');
        $config->save('concrete5_graphql_websocket_security::graphql_jwt.anonymus_refresh_count', (Int) 0);
        $config->save('concrete5_graphql_websocket_security::graphql_jwt.anonymus_revoked', (Boolean) false);
        $config->save('concrete5_graphql_websocket_security::graphql_jwt.anonymus_token_expires', (Int) 0);
        $config->save('concrete5_graphql_websocket_security::graphql_jwt.anonymus_refresh_token_expires', (Int) 0);
    }

    public function setSecret($secret)
    {
        $config = App::make('config');
        $config->save('concrete5_graphql_websocket_security::graphql_jwt.anonymus_secret', (String) $secret);
    }

    public function getSecret()
    {
        $config = App::make('config');
        return (String) $config->get('concrete5_graphql_websocket_security::graphql_jwt.anonymus_secret');
    }

    public function setRefreshCount($count)
    {
        $config = App::make('config');
        $config->save('concrete5_graphql_websocket_security::graphql_jwt.anonymus_refresh_count', (Int) $count);
    }

    public function getRefreshCount()
    {
        $config = App::make('config');
        return (Int) $config->get('concrete5_graphql_websocket_security::graphql_jwt.anonymus_refresh_count');
    }

    public function setRevoked($revoked)
    {
        $config = App::make('config');
        $config->save('concrete5_graphql_websocket_security::graphql_jwt.anonymus_revoked', (Boolean) $revoked);
    }

    public function getRevoked()
    {
        $config = App::make('config');
        return (Boolean) $config->get('concrete5_graphql_websocket_security::graphql_jwt.anonymus_revoked');
    }

    public function setTokenExpires($expires)
    {
        $config = App::make('config');
        $config->save('concrete5_graphql_websocket_security::graphql_jwt.anonymus_token_expires', (Int) $expires);
    }

    public function setRefreshTokenExpires($expires)
    {
        $config = App::make('config');
        $config->save('concrete5_graphql_websocket_security::graphql_jwt.anonymus_refresh_token_expires', (Int) $expires);
    }

    public function getNotBefore()
    {
        $config = App::make('config');
        return (Int) $config->get('concrete5_graphql_websocket_security::graphql_jwt.anonymus_get_not_before');
    }
}
