<?php

namespace Concrete\Package\Concrete5GraphqlWebsocketSecurity;

use Concrete\Core\Package\Package;
use Concrete\Core\Database\EntityManager\Provider\StandardPackageProvider;
use Concrete\Core\Routing\RouterInterface;

class Controller extends Package
{
    /**
     * {@inheritdoc}
     *
     * @see \Concrete\Core\Package\Package::$packageDependencies
     */
    protected $packageDependencies = [
        'concrete5_graphql_websocket' => '1.3.2'
    ];
    protected $appVersionRequired = '8.5.1';
    protected $pkgVersion = '0.0.1';
    protected $pkgHandle = 'concrete5_graphql_websocket_security';
    protected $pkgName = 'GraphQL with Websocket Security';
    protected $pkgDescription = 'Helps to use GraphQL and Websocket in Concrete5 securley';
    protected $pkg;
    protected $pkgAutoloaderRegistries = [
        'src/GraphQl' => '\GraphQl',
        'src/Helpers' => '\Helpers'
    ];

    public function getEntityManagerProvider()
    {
        $provider = new StandardPackageProvider($this->app, $this, [
            'src/Entity' => 'Entity',
        ]);

        return $provider;
    }

    public function on_start()
    {
        $this->app->extend(ServerInterface::class, function (ServerInterface $server) {
            return $server->addMiddleware($this->app->make(\Helpers\Middleware::class));
        });
        $this->app->make(RouterInterface::class)->register('/graphql', 'Helpers\Api::view');
        // $al = AssetList::getInstance();
        // $al->register('javascript', 'concrete5_graphql_websocket_security', 'js/dist/concrete5_graphql_websocket_security.js', array('position' => Asset::ASSET_POSITION_FOOTER, 'minify' => false, 'combine' => true), $this);
        $this->app->singleton('\Helpers\Auth');
        \GraphQl\Security::start();
    }
}
