<?php
namespace GraphQl;

use GraphQl\SecurityResolver;
use Concrete5GraphqlWebsocket\SchemaBuilder;

class ScreenGraphQl
{
    public static function start()
    {
        SchemaBuilder::registerSchemaFileForMerge(__DIR__ . '/security.gql');
        SchemaBuilder::registerResolverForMerge(SecurityResolver::get());
    }
}
