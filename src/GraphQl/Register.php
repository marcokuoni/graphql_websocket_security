<?php

namespace GraphQl;

use GraphQl\SecurityResolver;
use GraphQl\UserManagementResolver;
use Concrete5GraphqlWebsocket\SchemaBuilder;

class Register
{
    public static function start()
    {
        SchemaBuilder::registerSchemaFileForMerge(__DIR__ . '/security.gql');
        SchemaBuilder::registerResolverForMerge(SecurityResolver::get());

        SchemaBuilder::registerSchemaFileForMerge(__DIR__ . '/userManagement.gql');
        SchemaBuilder::registerResolverForMerge(UserManagementResolver::get());
    }
}
