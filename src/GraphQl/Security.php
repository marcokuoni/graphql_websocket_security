<?php

namespace GraphQl;

use GraphQl\SecurityResolver;
use GraphQl\UserResolver;
use Concrete5GraphqlWebsocket\SchemaBuilder;

class Security
{
    public static function start()
    {
        SchemaBuilder::registerSchemaFileForMerge(__DIR__ . '/security.gql');
        SchemaBuilder::registerResolverForMerge(SecurityResolver::get());

        SchemaBuilder::registerSchemaFileForMerge(__DIR__ . '/user.gql');
        SchemaBuilder::registerResolverForMerge(UserResolver::get());
    }
}
