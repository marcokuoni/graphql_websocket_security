<?php

namespace GraphQl;

use GraphQl\SecurityResolver;
use Concrete5GraphqlWebsocket\SchemaBuilder;
use Siler\GraphQL as SilerGraphQL;
use Concrete\Core\Support\Facade\Application as App;

class Security
{
    public static function start()
    {
        SchemaBuilder::registerSchemaFileForMerge(__DIR__ . '/security.gql');
        SchemaBuilder::registerResolverForMerge(SecurityResolver::get());

        SilerGraphQL\listen(SilerGraphQL\ON_CONNECT, function ($context) {
            $user = null;

            $tokenHelper = App::make(\Helpers\Token::class);
            if (is_array($context)) {
                $context = $context['Authorization'];
            }
            $token = $tokenHelper->getTokenFromAuthHeader($context);
            if ($token) {
                $authorize = App::make(\Helpers\Authorize::class);
                $user = $authorize->authenticated($token);

                if ($user) {
                    $authenticate = App::make(\Helpers\Authenticate::class);
                    $authenticate->logRequest($user);
                }
            }

            return ['user' => $user];
        });
    }
}
