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
        }
        $auth_expire = (int) $config->get('concrete5_graphql_websocket_security::graphql_jwt.auth_expire');
        $this->set('auth_expire', $auth_expire);

        $auth_refresh_expire = (int) $config->get('concrete5_graphql_websocket_security::graphql_jwt.auth_refresh_expire');
        $this->set('auth_refresh_expire', $auth_refresh_expire);

        $log_requests = (bool) $config->get('concrete5_graphql_websocket_security::graphql_jwt.log_requests');
        $this->set('log_requests', $log_requests);

        $just_with_valid_token = (bool) $config->get('concrete5_graphql_websocket_security::graphql_jwt.just_with_valid_token');
        $this->set('just_with_valid_token', $just_with_valid_token);

        $one_time_auto_refresh = (bool) $config->get('concrete5_graphql_websocket_security::graphql_jwt.one_time_auto_refresh');
        $this->set('one_time_auto_refresh', $one_time_auto_refresh);

        $cookie_name = (String) $config->get('concrete5_graphql_websocket_security::graphql_jwt.cookie.cookie_name');
        $this->set('cookie_name', $cookie_name);

        $cookie_lifetime = (Int) $config->get('concrete5_graphql_websocket_security::graphql_jwt.cookie.cookie_lifetime');
        $this->set('cookie_lifetime', $cookie_lifetime);

        $cookie_domain = (String) $config->get('concrete5_graphql_websocket_security::graphql_jwt.cookie.cookie_domain');
        $this->set('cookie_domain', $cookie_domain);

        $cookie_secure = (Bool) $config->get('concrete5_graphql_websocket_security::graphql_jwt.cookie.cookie_secure');
        $this->set('cookie_secure', $cookie_secure);
    }

    public function update_entity_settings()
    {
        if (!$this->token->validate('update_entity_settings')) {
            $this->error->add($this->token->getErrorMessage());
        }

        if (!$this->error->has()) {
            if ($this->isPost()) {
                $config = $this->app->make('config');
                $lr = $this->post('log_requests') === 'yes';
                $jwvt = $this->post('just_with_valid_token') === 'yes';
                $otar = $this->post('one_time_auto_refresh') === 'yes';
                $cs = $this->post('cookie_secure') === 'yes';
                $auth_expire = (int) $this->post('auth_expire');
                $auth_refresh_expire = (int) $this->post('auth_refresh_expire');
                $cookie_name = (String) $this->post('cookie_name');
                $cookie_lifetime = (Int) $this->post('cookie_lifetime');
                $cookie_domain = (String) $this->post('cookie_domain');

                $currentUser = App::make(User::class);
                if ((int) $currentUser->getUserID() === 1) {
                    $config->save('concrete5_graphql_websocket_security::graphql_jwt.auth_secret_key', (string) $this->post('auth_secret_key'));
                    $config->save('concrete5_graphql_websocket_security::graphql_jwt.auth_refresh_secret_key', (string) $this->post('auth_refresh_secret_key'));
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

                if ($cookie_lifetime > 0) {
                    $config->save('concrete5_graphql_websocket_security::graphql_jwt.cookie.cookie_lifetime', $cookie_lifetime);
                }

                if (isset($cookie_domain) && $cookie_domain !== '') {
                    $config->save('concrete5_graphql_websocket_security::graphql_jwt.cookie.cookie_domain', $cookie_domain);
                }

                $config->save('concrete5_graphql_websocket_security::graphql_jwt.cookie.cookie_secure', $cs);
                $config->save('concrete5_graphql_websocket_security::graphql_jwt.log_requests', $lr);
                $config->save('concrete5_graphql_websocket_security::graphql_jwt.just_with_valid_token', $jwvt);
                $config->save('concrete5_graphql_websocket_security::graphql_jwt.one_time_auto_refresh', $otar);

                $this->flash('success', t('Settings updated.'));
                $this->redirect('/dashboard/system/environment/graphql_security', 'view');
            }
        } else {
            $this->set('error', [$this->token->getErrorMessage()]);
        }
    }
}
