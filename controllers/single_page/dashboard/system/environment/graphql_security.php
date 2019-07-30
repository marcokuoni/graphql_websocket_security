<?php

namespace Concrete\Package\Concrete5GraphqlWebsocketSecurity\Controller\SinglePage\Dashboard\System\Environment;

use Concrete\Core\Page\Controller\DashboardPageController;
use Concrete\Core\Support\Facade\Application as App;
use Concrete\Core\User\User;
use Doctrine\ORM\EntityManagerInterface;
use Entity\AnonymusUser as AnonymusUserEntity;

class GraphqlSecurity extends DashboardPageController
{
    public function view()
    {
        $config = $this->app->make('config');
        $currentUser = App::make(User::class);
        if ((int) $currentUser->getUserID() === 1) {
            $auth_secret_key = (string) $config->get('concrete5_graphql_websocket_security::graphql_jwt.auth_secret_key');
            $this->set('auth_secret_key', $auth_secret_key);
        }
        $auth_expire = (int) $config->get('concrete5_graphql_websocket_security::graphql_jwt.auth_expire');
        $this->set('auth_expire', $auth_expire);

        $log_anonymus_users = (bool) $config->get('concrete5_graphql_websocket_security::graphql_jwt.log_anonymus_users');
        $this->set('log_anonymus_users', $log_anonymus_users);
        if ($log_anonymus_users) {
            $entityManager = App::make(EntityManagerInterface::class);
            $anonymusUserRepository = $entityManager->getRepository(AnonymusUserEntity::class);
            $anonymusUsers = $anonymusUserRepository->findAll();
            $this->set('anonymusUsers', $anonymusUsers);
        }
    }

    public function update_entity_settings()
    {
        if (!$this->token->validate('update_entity_settings')) {
            $this->error->add($this->token->getErrorMessage());
        }

        if (!$this->error->has()) {
            if ($this->isPost()) {
                $config = $this->app->make('config');
                $lau = $this->post('log_anonymus_users') === 'yes';

                $currentUser = App::make(User::class);
                if ((int) $currentUser->getUserID() === 1) {
                    $config->save('concrete5_graphql_websocket_security::graphql_jwt.auth_secret_key', (string) $this->post('auth_secret_key'));
                }

                $config->save('concrete5_graphql_websocket_security::graphql_jwt.auth_expire', (int) $this->post('auth_expire'));
                $config->save('concrete5_graphql_websocket_security::graphql_jwt.log_anonymus_users', $lau);

                $this->flash('success', t('Settings updated.'));
                $this->redirect('/dashboard/system/environment/graphql_security', 'view');
            }
        } else {
            $this->set('error', [$this->token->getErrorMessage()]);
        }
    }
}
