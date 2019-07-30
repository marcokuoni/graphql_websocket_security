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
    protected $pkgVersion = '0.0.3';
    protected $pkgHandle = 'concrete5_graphql_websocket_security';
    protected $pkgName = 'GraphQL with Websocket Security';
    protected $pkgDescription = 'Helps to use GraphQL and Websocket in Concrete5 securley';
    protected $pkg;
    protected $pkgAutoloaderRegistries = [
        'src/GraphQl' => '\GraphQl',
        'src/Helpers' => '\Helpers',
        'src/Entity' => '\Entity',
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
        $this->registerAutoload();
        $this->app->extend(ServerInterface::class, function (ServerInterface $server) {
            return $server->addMiddleware($this->app->make(\Helpers\Middleware::class));
        });
        $this->app->make(RouterInterface::class)->register('/graphql', 'Helpers\Api::view');

        $this->app->singleton('\Helpers\Authorize');
        $this->app->singleton('\Helpers\Authenticate');

        \GraphQl\Security::start();
    }

    public function install()
    {
        parent::install();
        $this->installXML();
    }

    public function upgrade()
    {
        parent::upgrade();
        $this->installXML();
    }

    private function installXML()
    {
        $this->installContentFile('config/install.xml');
    }

    private function registerAutoload()
    {
        $autoloader = $this->getPackagePath() . '/vendor/autoload.php';
        if (file_exists($autoloader)) {
            require_once $autoloader;
        }
    }


    // public static function installUserAttributes(Package $package)
    // {
    //     //user attributes for customers
    //     $uakc = AttributeKeyCategory::getByHandle('user');
    //     $uakc->setAllowAttributeSets(AttributeKeyCategory::ASET_ALLOW_MULTIPLE);

    //     //define attr group, and the different attribute types we'll use
    //     $custSet = AttributeSet::getByHandle('customer_info');
    //     if (!is_object($custSet)) {
    //         $custSet = $uakc->addSet('customer_info', t('Store Customer Info'), $pkg);
    //     }
    //     $text = AttributeType::getByHandle('text');
    //     $address = AttributeType::getByHandle('address');
    //     $dateTime = AttributeType::getByHandle('date_time');

    //     Installer::installUserAttribute('email', $text, $pkg, $custSet);
    //     Installer::installUserAttribute('billing_first_name', $text, $pkg, $custSet);
    //     Installer::installUserAttribute('billing_last_name', $text, $pkg, $custSet);
    //     Installer::installUserAttribute('billing_address', $address, $pkg, $custSet);
    //     Installer::installUserAttribute('billing_phone', $text, $pkg, $custSet);
    //     Installer::installUserAttribute('billing_birthdate', $dateTime, $pkg, $custSet);
    //     Installer::installUserAttribute('shipping_first_name', $text, $pkg, $custSet);
    //     Installer::installUserAttribute('shipping_last_name', $text, $pkg, $custSet);
    //     Installer::installUserAttribute('shipping_address', $address, $pkg, $custSet);
    // }
    // public static function installUserAttribute($handle, $type, $pkg, $set, $data = null)
    // {
    //     $attr = UserAttributeKey::getByHandle($handle);
    //     if (!is_object($attr)) {
    //         $name = Core::make("helper/text")->camelcase($handle);
    //         if (!$data) {
    //             $data = array(
    //                 'akHandle' => $handle,
    //                 'akName' => t($name),
    //                 'akIsSearchable' => false,
    //                 'uakProfileEdit' => true,
    //                 'uakProfileEditRequired' => false,
    //                 'uakRegisterEdit' => false,
    //                 'uakProfileEditRequired' => false,
    //                 'akCheckedByDefault' => true
    //             );
    //         }
    //         UserAttributeKey::add($type, $data, $pkg)->setAttributeSet($set);
    //     }
    // }
}
