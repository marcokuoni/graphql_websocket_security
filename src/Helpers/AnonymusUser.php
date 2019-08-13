<?php

namespace Helpers;

use Concrete\Core\Support\Facade\Application as App;
use Concrete\Core\Foundation\ConcreteObject;
use Concrete\Core\Support\Facade\Application;
use Doctrine\ORM\EntityManagerInterface;
use Entity\AnonymusUser as AnonymusUserEntity;
use Concrete\Core\Localization\Localization;
use Concrete\Core\Http\Request;
use Concrete\Core\Permission\IPService;

class AnonymusUser extends ConcreteObject
{
    public function getAnonymusUser($uID = null)
    {
        $entityManager = App::make(EntityManagerInterface::class);
        $anonymusUserRepository = $entityManager->getRepository(AnonymusUserEntity::class);
        $app = App::getFacadeApplication();
        $session = $app['session'];
        $config = $app->make('config');

        if ($uID !== null && $uID > 0) {
            if ((bool) $config->get('concrete5_graphql_websocket_security::graphql_jwt.log_anonymus_users')) {
                return $anonymusUserRepository->findOneBy(['uID' => $uID]);
            } else {
                if ($session->has('anonymusUser') && $session->has('auID') && $uID == $session->get('auID')) {
                    return $session->get('anonymusUser');
                } else {
                    return null;
                }
            }
        } else {
            if ($session->has('auID') && $session->get('anonymus')) {
                $uID = $session->get('auID');

                if ((bool) $config->get('concrete5_graphql_websocket_security::graphql_jwt.log_anonymus_users')) {
                    $user = $anonymusUserRepository->findOneBy(['uID' => $uID]);
                } else {
                    $user = $session->get('anonymusUser');
                }
                
                if (!empty($user)) {
                    return $user;
                }
            }

            $uName = uniqid('graphql_jwt_user_id');
            $ipService = $app->make(IPService::class);
            $request = $app->make(Request::class);
            $ip = (string) $ipService->getRequestIPAddress();
            $userAgent = $request->server->get('HTTP_USER_AGENT');
            $timezone = date_default_timezone_get();
            $language = Localization::activeLocale();

            $item = new AnonymusUserEntity();

            $item->setUserName($uName);

            $item->setUserLastIP($ip);
            $item->setUserLastAgent($userAgent);
            $item->setUserTimezone($timezone);
            $item->setUserDefaultLanguage($language);
            $entityManager->persist($item);

            if ((bool) $config->get('concrete5_graphql_websocket_security::graphql_jwt.log_anonymus_users')) {
                $entityManager->flush();
            } else {
                $item->setUserID($uName);
                $session->set('anonymusUser', $item);
            }

            $session->set('auID', $item->getUserID() ? $item->getUserID() : $uName);
            $session->set('auName', $uName);
            $session->set('anonymus', get_class($item) === AnonymusUserEntity::class);
            $session->set('auBlockTypesSet', false);
            $session->set('auLastOnline', time());
            $session->set('auTimezone', $timezone);
            $session->set('auDefaultLanguage', $language);
            $session->set('auLastPasswordChange', false);
            $session->set('auActive', true);

            $cookie = $app['cookie'];
            $cookie->set(sprintf('%s_LOGIN', $app['config']->get('concrete.session.name')), 1);

            return $item;
        }
    }

    public function delete($user)
    {
        $app = App::getFacadeApplication();
        $config = App::make('config');

        if ((bool) $config->get('concrete5_graphql_websocket_security::graphql_jwt.log_anonymus_users')) {
            $entityManager = App::make(EntityManagerInterface::class);

            $entityManager->createQueryBuilder()
                ->delete(AnonymusUserEntity::class, 'r')
                ->where('r.uID < :uID')
                ->setParameter('uID', $user->getUserID())
                ->getQuery()->execute();
        } else {
            $session = $app['session'];
            $session->remove('anonymusUser');
        }
    }

    public function setSecret($user, $secret)
    {
        $app = App::getFacadeApplication();
        $config = App::make('config');

        if ((bool) $config->get('concrete5_graphql_websocket_security::graphql_jwt.log_anonymus_users')) {
            $entityManager = App::make(EntityManagerInterface::class);
            $anonymusUserRepository = $entityManager->getRepository(AnonymusUserEntity::class);

            $item = $anonymusUserRepository->findOneBy(['uID' => $user->getUserID()]);

            $item->setUserGraphqlJwtAuthSecret($secret);

            $entityManager->persist($item);
            $entityManager->flush();
        } else {
            $session = $app['session'];
            $item = $session->get('anonymusUser');
            $item->setUserGraphqlJwtAuthSecret($secret);
            $session->set('anonymusUser', $item);
        }
    }

    public function getSecret($user)
    {
        $app = App::getFacadeApplication();
        $config = App::make('config');

        if ((bool) $config->get('concrete5_graphql_websocket_security::graphql_jwt.log_anonymus_users')) {
            $entityManager = App::make(EntityManagerInterface::class);
            $anonymusUserRepository = $entityManager->getRepository(AnonymusUserEntity::class);

            $item = $anonymusUserRepository->findOneBy(['uID' => $user->getUserID()]);
        } else {
            $session = $app['session'];
            $item = $session->get('anonymusUser');
        }

        return $item->getUserGraphqlJwtAuthSecret();
    }

    public function setRevoked($user, $revoked)
    {
        $app = App::getFacadeApplication();
        $config = App::make('config');

        if ((bool) $config->get('concrete5_graphql_websocket_security::graphql_jwt.log_anonymus_users')) {
            $entityManager = App::make(EntityManagerInterface::class);
            $anonymusUserRepository = $entityManager->getRepository(AnonymusUserEntity::class);

            $item = $anonymusUserRepository->findOneBy(['uID' => $user->getUserID()]);

            $item->setUserGraphqlJwtAuthSecretRevoked($revoked);

            $entityManager->persist($item);
            $entityManager->flush();
        } else {
            $session = $app['session'];
            $item = $session->get('anonymusUser');
            $item->setUserGraphqlJwtAuthSecretRevoked($revoked);
            $session->set('anonymusUser', $item);
        }
    }

    public function getRevoked($user)
    {
        $app = App::getFacadeApplication();
        $config = App::make('config');

        if ((bool) $config->get('concrete5_graphql_websocket_security::graphql_jwt.log_anonymus_users')) {
            $entityManager = App::make(EntityManagerInterface::class);
            $anonymusUserRepository = $entityManager->getRepository(AnonymusUserEntity::class);

            $item = $anonymusUserRepository->findOneBy(['uID' => $user->getUserID()]);
        } else {
            $session = $app['session'];
            $item = $session->get('anonymusUser');
        }

        return $item->getUserGraphqlJwtAuthSecretRevoked();
    }

    public function setTokenExpires($user, $expires)
    {
        $app = App::getFacadeApplication();
        $config = App::make('config');

        if ((bool) $config->get('concrete5_graphql_websocket_security::graphql_jwt.log_anonymus_users')) {
            $entityManager = App::make(EntityManagerInterface::class);
            $anonymusUserRepository = $entityManager->getRepository(AnonymusUserEntity::class);

            $item = $anonymusUserRepository->findOneBy(['uID' => $user->getUserID()]);

            $item->setUserGraphqlJwtTokenExpires($expires);

            $entityManager->persist($item);
            $entityManager->flush();
        } else {
            $session = $app['session'];
            $item = $session->get('anonymusUser');
            $item->setUserGraphqlJwtRefreshTokenExpires($expires);
            $session->set('anonymusUser', $item);
        }
    }

    public function setRefreshTokenExpires($user, $expires)
    {
        $app = App::getFacadeApplication();
        $config = App::make('config');

        if ((bool) $config->get('concrete5_graphql_websocket_security::graphql_jwt.log_anonymus_users')) {
            $entityManager = App::make(EntityManagerInterface::class);
            $anonymusUserRepository = $entityManager->getRepository(AnonymusUserEntity::class);

            $item = $anonymusUserRepository->findOneBy(['uID' => $user->getUserID()]);

            $item->setUserGraphqlJwtRefreshTokenExpires($expires);

            $entityManager->persist($item);
            $entityManager->flush();
        } else {
            $session = $app['session'];
            $item = $session->get('anonymusUser');
            $item->setUserGraphqlJwtRefreshTokenExpires($expires);
            $session->set('anonymusUser', $item);
        }
    }

    public function getNotBefore($user)
    {
        $app = App::getFacadeApplication();
        $config = App::make('config');

        if ((bool) $config->get('concrete5_graphql_websocket_security::graphql_jwt.log_anonymus_users')) {
            $entityManager = App::make(EntityManagerInterface::class);
            $anonymusUserRepository = $entityManager->getRepository(AnonymusUserEntity::class);

            $item = $anonymusUserRepository->findOneBy(['uID' => $user->getUserID()]);
        } else {
            $session = $app['session'];
            $item = $session->get('anonymusUser');
        }

        return $item->getUserGraphqlJwtTokenNotBefore();
    }

    public function logRequest($user, $currentTime, $ip, $userAgent, $timezone, $language)
    {
        $config = App::make('config');

        if ((bool) $config->get('concrete5_graphql_websocket_security::graphql_jwt.log_anonymus_users')) {
            $entityManager = App::make(EntityManagerInterface::class);
            $anonymusUserRepository = $entityManager->getRepository(AnonymusUserEntity::class);

            $item = $anonymusUserRepository->findOneBy(['uID' => $user->getUserID()]);

            $item->setUserGraphqlJwtLastRequest($currentTime);
            $item->setUserGraphqlJwtLastRequestIp($ip);
            $item->setUserGraphqlJwtLastRequestAgent($userAgent);
            $item->setUserGraphqlJwtLastRequestTimezone($timezone);
            $item->setUserGraphqlJwtLastRequestLanguage($language);
            $item->setUserGraphqlJwtRequestCount($item->getUserGraphqlJwtRequestCount() > 0 ? ($item->getUserGraphqlJwtRequestCount() + 1) : 1);
            $entityManager->persist($item);
            $entityManager->flush();
        }
    }
}
