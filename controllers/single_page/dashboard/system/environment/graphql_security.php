<?php

namespace Concrete\Package\Concrete5GraphqlWebsocketSecurity\Controller\SinglePage\Dashboard\System\Environment;

use Concrete\Core\Page\Controller\DashboardPageController;
use Concrete\Core\Support\Facade\Application as App;
use Concrete\Core\User\User;

class GraphqlSecurity extends DashboardPageController
{
    public function view()
    {
        $config = $this->app->make('config');
        $currentUser = App::make(User::class);
        if ((int) $currentUser->getUserID() === 1) {
            $auth_secret_key = (string) $config->get('concrete5_graphql_websocket_security::graphql_jwt.auth_secret_key');
            $this->set('auth_secret_key', $auth_secret_key);
            $auth_refresh_secret_key = (string) $config->get('concrete5_graphql_websocket_security::graphql_jwt.auth_refresh_secret_key');
            $this->set('auth_refresh_secret_key', $auth_refresh_secret_key);

            $corsOrigins = (string) implode(', ', $config->get('concrete5_graphql_websocket_security::graphql_jwt.corsOrigins'));
            $this->set('corsOrigins', $corsOrigins);
        }
        $auth_expire = (int) $config->get('concrete5_graphql_websocket_security::graphql_jwt.auth_expire');
        $this->set('auth_expire', $auth_expire);

        $auth_refresh_expire = (int) $config->get('concrete5_graphql_websocket_security::graphql_jwt.auth_refresh_expire');
        $this->set('auth_refresh_expire', $auth_refresh_expire);

        $cookie_name = (string) $config->get('concrete5_graphql_websocket_security::graphql_jwt.cookie.cookie_name');
        $this->set('cookie_name', $cookie_name);

        $cookie_lifetime = (int) $config->get('concrete5_graphql_websocket_security::graphql_jwt.cookie.cookie_lifetime');
        $this->set('cookie_lifetime', $cookie_lifetime);

        $cookie_domain = (string) $config->get('concrete5_graphql_websocket_security::graphql_jwt.cookie.cookie_domain');
        $this->set('cookie_domain', $cookie_domain);

        $cookie_path = (string) $config->get('concrete5_graphql_websocket_security::graphql_jwt.cookie.cookie_path');
        $this->set('cookie_path', $cookie_path);

        $cookie_secure = (bool) $config->get('concrete5_graphql_websocket_security::graphql_jwt.cookie.cookie_secure');
        $this->set('cookie_secure', $cookie_secure);

        $cookie_same_site = (string) $config->get('concrete5_graphql_websocket_security::graphql_jwt.cookie.cookie_same_site');
        $this->set('cookie_same_site', $cookie_same_site);
    }

    public function update_entity_settings()
    {
        if (!$this->token->validate('update_entity_settings')) {
            $this->error->add($this->token->getErrorMessage());
        }

        if (!$this->error->has()) {
            if ($this->isPost()) {
                $config = $this->app->make('config');
                $cs = $this->post('cookie_secure') === 'yes';
                $same_site = (string) $this->post('cookie_same_site');
                $auth_expire = (int) $this->post('auth_expire');
                $auth_refresh_expire = (int) $this->post('auth_refresh_expire');
                $cookie_name = (string) $this->post('cookie_name');
                $cookie_lifetime = $auth_refresh_expire;
                $cookie_domain = (string) $this->post('cookie_domain');
                $cookie_path = (string) $this->post('cookie_path');
                $corsOrigins = (string) $this->post('corsOrigins');

                $currentUser = App::make(User::class);
                if ((int) $currentUser->getUserID() === 1) {
                    $config->save('concrete5_graphql_websocket_security::graphql_jwt.auth_secret_key', (string) $this->post('auth_secret_key'));
                    $config->save('concrete5_graphql_websocket_security::graphql_jwt.auth_refresh_secret_key', (string) $this->post('auth_refresh_secret_key'));

                    if (isset($corsOrigins) && $corsOrigins !== '') {
                        $config->save('concrete5_graphql_websocket_security::graphql_jwt.corsOrigins', explode(',', $corsOrigins));
                    }
                }

                if ($auth_expire > 0) {
                    $config->save('concrete5_graphql_websocket_security::graphql_jwt.auth_expire', $auth_expire);
                }

                if ($auth_refresh_expire > 0) {
                    $config->save('concrete5_graphql_websocket_security::graphql_jwt.auth_refresh_expire', $auth_refresh_expire);
                }

                if (isset($cookie_name) && $cookie_name !== '') {
                    $config->save('concrete5_graphql_websocket_security::graphql_jwt.cookie.cookie_name', $cookie_name);
                }

                if (isset($cookie_path) && $cookie_path !== '') {
                    $config->save('concrete5_graphql_websocket_security::graphql_jwt.cookie.cookie_path', $cookie_path);
                }

                if ($cookie_lifetime > 0) {
                    $config->save('concrete5_graphql_websocket_security::graphql_jwt.cookie.cookie_lifetime', $cookie_lifetime);
                }

                if (isset($cookie_domain) && $cookie_domain !== '') {
                    $config->save('concrete5_graphql_websocket_security::graphql_jwt.cookie.cookie_domain', $cookie_domain);
                }

                $config->save('concrete5_graphql_websocket_security::graphql_jwt.cookie.cookie_secure', $cs);

                $config->save('concrete5_graphql_websocket_security::graphql_jwt.cookie.cookie_same_site', $same_site);

                $this->flash('success', t('Settings updated.'));
                $this->redirect('/dashboard/system/environment/graphql_security', 'view');
            }
        } else {
            $this->set('error', [$this->token->getErrorMessage()]);
        }
    }
}
