<?php

namespace Concrete\Package\Concrete5GraphqlWebsocketSecurity;

use Concrete\Core\Package\Package;
use Concrete\Core\Database\EntityManager\Provider\StandardPackageProvider;
use Concrete\Core\Routing\RouterInterface;
use Concrete\Core\Attribute\Key\Category as AttributeKeyCategory;
use Concrete\Core\Attribute\Type as AttributeType;
use Concrete\Core\Attribute\Set as AttributeSet;
use Concrete\Core\Attribute\Key\UserKey as UserAttributeKey;
use Concrete\Core\Job\Job;

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
    protected $pkgVersion = '1.1.3';
    protected $pkgHandle = 'concrete5_graphql_websocket_security';
    protected $pkgName = 'GraphQL with Websocket Security';
    protected $pkgDescription = 'Helps to use GraphQL and Websocket in Concrete5 securley';
    protected $pkgAutoloaderRegistries = [
        'src/GraphQl' => '\GraphQl',
        'src/Helpers' => '\Helpers',
    ];

    public function on_start()
    {
        $this->registerAutoload();

        $this->app->singleton('\Helpers\Authorize');
        $this->app->singleton('\Helpers\Authenticate');
        $this->app->singleton('\Helpers\AnonymusUser');
        $this->app->singleton('\Helpers\Storage');
        $this->app->singleton('\Helpers\Token');

        $this->app->make(RouterInterface::class)->register('/graphql', 'Helpers\Api::view');
        $this->app->make(RouterInterface::class)->register('/refresh_token', 'Helpers\Authorize::refreshToken');
        $this->app->make(RouterInterface::class)->register('/logout_token', 'Helpers\Authorize::logoutToken');


        \GraphQl\Security::start();
    }

    public function install()
    {
        parent::install();
        $this->installXML();
        $this->installUserAttributes();
    }

    public function upgrade()
    {
        parent::upgrade();
        $this->installXML();
        $this->installUserAttributes();
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

    private function installUserAttributes()
    {
        $pkg = Package::getByHandle($this->pkgHandle);
        //user attributes for customers
        $uakc = AttributeKeyCategory::getByHandle('user');
        $uakc->setAllowAttributeSets(AttributeKeyCategory::ASET_ALLOW_MULTIPLE);

        //define attr group, and the different attribute types we'll use
        $custSet = AttributeSet::getByHandle('graphql_jwt');
        if (!is_object($custSet)) {
            $custSet = $uakc->addSet('graphql_jwt', t('GraphQL / Websocket Security'), $pkg);
        }
        $text = AttributeType::getByHandle('text');
        $number = AttributeType::getByHandle('number');
        $boolean = AttributeType::getByHandle('boolean');
        
        $this->installUserAttribute('graphql_jwt_auth_secret', 'Authorize secret', $text, $pkg, $custSet);
        $this->installUserAttribute('graphql_jwt_auth_secret_revoked', 'Authorize secret revoked', $boolean, $pkg, $custSet);
        $this->installUserAttribute('graphql_jwt_token_not_before', 'Token not before', $number, $pkg, $custSet);
        $this->installUserAttribute('graphql_jwt_token_expires', 'Token expires', $number, $pkg, $custSet);
        $this->installUserAttribute('graphql_jwt_refresh_token_expires', 'Refresh token expires', $number, $pkg, $custSet);
        $this->installUserAttribute('graphql_jwt_last_request', 'Last request', $number, $pkg, $custSet);
        $this->installUserAttribute('graphql_jwt_last_request_ip', 'Last request IP', $text, $pkg, $custSet);
        $this->installUserAttribute('graphql_jwt_last_request_agent', 'Last request agent', $text, $pkg, $custSet);
        $this->installUserAttribute('graphql_jwt_last_request_timezone', 'Last request timezone', $text, $pkg, $custSet);
        $this->installUserAttribute('graphql_jwt_last_request_language', 'Last request language', $text, $pkg, $custSet);
        $this->installUserAttribute('graphql_jwt_request_count', 'Request count', $number, $pkg, $custSet);
        $this->installUserAttribute('graphql_jwt_auth_refresh_count', 'Refresh count', $number, $pkg, $custSet);
    }

    private function installUserAttribute($handle, $name, $type, $pkg, $set, $data = null)
    {
        $attr = UserAttributeKey::getByHandle($handle);
        if (!is_object($attr)) {
            if (!$data) {
                $data = array(
                    'akHandle' => $handle,
                    'akName' => t($name),
                    'akIsSearchable' => false,
                    'uakProfileEdit' => true,
                    'uakProfileEditRequired' => false,
                    'uakRegisterEdit' => false,
                    'uakProfileEditRequired' => false,
                    'akCheckedByDefault' => true
                );
            }
            UserAttributeKey::add($type, $data, $pkg)->setAttributeSet($set);
        }
    }
}
