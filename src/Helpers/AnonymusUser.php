<?php

namespace Helpers;

use Concrete\Core\Foundation\ConcreteObject;
use Concrete\Core\Support\Facade\Application;
use Concrete\Core\Authentication\AuthenticationType;
use Doctrine\ORM\EntityManagerInterface;
use Entity\AnonymusUser as AnonymusUserEntity;
use Concrete\Core\Localization\Localization;
use Concrete\Core\Http\Request;
use Concrete\Core\Permission\IPService;
use Database;

class AnonymusUser extends ConcreteObject
{
    public $uID = '';
    public $uName = '';
    public $anonymus = true;

    /**
     * @return bool
     */
    public function checkLogin()
    {
        $app = Application::getFacadeApplication();
        $session = $app['session'];
        $config = $app['config'];

        $invalidate = $app->make('Concrete\Core\Session\SessionValidatorInterface')->handleSessionValidation($session);
        if ($invalidate) {
            $this->loadError(USER_SESSION_EXPIRED);
        }

        if ($session->get('uID') > 0) {
            $this->uID = $session->get('uID');
            $this->uName = $session->get('uName');
            $this->anonymus = $session->get('anonymus');

            $checkUID = (isset($this->uID)) ? ($this->uID) : (false);

            if ($checkUID == $session->get('uID')) {
                $session->set('uOnlineCheck', time());
                if (($session->get('uOnlineCheck') - $session->get('uLastOnline') > (ONLINE_NOW_TIMEOUT / 2))) {
                    $session->set('uLastOnline', $session->get('uOnlineCheck'));
                }

                return true;
            } else {
                return false;
            }
        }

        return false;
    }

    public function __construct()
    {
        $app = Application::getFacadeApplication();
        $session = $app['session'];
        $config = $app->make('config');

        if ($session->has('uID') && $session->get('anonymus')) {
            $this->uID = $session->get('uID');
            $this->uName = $session->get('uName');
            $this->anonymus = $session->get('anonymus');
        } else {
            $this->uID = uniqid('graphql_jwt_user_id');
            $this->uName = uniqid('graphql_jwt_user_id');
            $this->anonymus = true;

            if ((bool) $config->get('concrete5_graphql_websocket_security::graphql_jwt.log_anonymus_users')) {
                $entityManager = $app->make(EntityManagerInterface::class);
                $anonymusUserRepository = $entityManager->getRepository(AnonymusUserEntity::class);

                if ($anonymusUserRepository->findOneBy(['uName' => $this->uName]) === null) {
                    $ipService = $app->make(IPService::class);
                    $request = $app->make(Request::class);
                    $ip = (string) $ipService->getRequestIPAddress();
                    $userAgent = $request->server->get('HTTP_USER_AGENT');

                    $item = new AnonymusUserEntity();

                    $item->setUserName($this->uName);
                    $item->setUserLastIP($ip);
                    $item->setUserLastAgent($userAgent);
                    $item->setUserTimezone(date_default_timezone_get());
                    $item->setUserDefaultLanguage(Localization::activeLocale());
                    $entityManager->persist($item);
                } else {
                    throw new \Exception(t('Anonymus user already exists?'));
                }
                $entityManager->flush();
                $this->uID = $item->getUserID();
            }

            $session->set('uID', $this->uID);
            $session->set('uName', $this->uName);
            $session->set('anonymus', $this->anonymus);

            $cookie = $app['cookie'];
            $cookie->set(sprintf('%s_LOGIN', $app['config']->get('concrete.session.name')), 1);
        }
    }

    public function getAnonymus()
    {
        return $this->anonymus;
    }

    /**
     * @return string|null
     */
    public function getUserName()
    {
        return $this->uName;
    }

    /**
     * @return bool
     */
    public function isRegistered()
    {
        return $this->getUserID() > 0;
    }

    /**
     * @return string
     */
    public function getUserID()
    {
        return $this->uID;
    }

    /**
     * @param string $authType
     * @throws \Exception
     */
    public function setAuthTypeCookie($authType)
    {
        $app = Application::getFacadeApplication();
        $config = $app['config'];
        $jar = $app['cookie'];

        $cookie = array($this->getUserID(), $authType);
        $at = AuthenticationType::getByHandle($authType);
        $cookie[] = $this->buildHash($this);

        $jar->set(
            'ccmAuthUserHash',
            implode(':', $cookie),
            time() + USER_FOREVER_COOKIE_LIFETIME,
            DIR_REL . '/',
            $config->get('concrete.session.cookie.cookie_domain'),
            $config->get('concrete.session.cookie.cookie_secure'),
            $config->get('concrete.session.cookie.cookie_httponly')
        );
    }

    private function buildHash($u, $test = 1)
    {
        if ($test > 10) {
            // This should only ever happen if by some stroke of divine intervention,
            // we end up pulling 10 hashes that already exist. the chances of this are very very low.
            throw new \Exception(t('There was a database error, try again.'));
        }
        $db = Database::connection();

        $validThrough = strtotime('+2 weeks');
        $token = $this->genString();
        try {
            $db->executeQuery(
                'INSERT INTO authTypeConcreteCookieMap (token, uID, validThrough) VALUES (?,?,?)',
                [$token, $u->getUserID(), $validThrough]
            );
        } catch (\Exception $e) {
            // HOLY CRAP.. SERIOUSLY?
            $this->buildHash($u, ++$test);
        }

        return $token;
    }

    private function genString($a = 16)
    {
        if (function_exists('random_bytes')) { // PHP7+
            return bin2hex(random_bytes($a));
        }
        if (function_exists('mcrypt_create_iv')) {
            // Use /dev/urandom if available, otherwise fall back to PHP's rand (below)
            // Don't use (MCRYPT_DEV_URANDOM|MCRYPT_RAND) here, because we prefer
            // openssl first.
            // Use @ here because otherwise mcrypt throws a noisy warning if
            // /dev/urandom is missing.
            $iv = @mcrypt_create_iv($a, MCRYPT_DEV_URANDOM);
            if ($iv !== false) {
                return bin2hex($iv);
            }
        }
        // don't use elseif, we need the fallthrough here.
        if (function_exists('openssl_random_pseudo_bytes')) {
            $iv = openssl_random_pseudo_bytes($a, $crypto_strong);
            if ($iv !== false && $crypto_strong) {
                return bin2hex($iv);
            }
        }
        // this means we've not yet returned, so MCRYPT_DEV_URANDOM isn't available.
        if (function_exists('mcrypt_create_iv')) {
            // terrible, but still better than what we're doing below
            $iv = mcrypt_create_iv($a, MCRYPT_RAND);
            if ($iv !== false) {
                return bin2hex($iv);
            }
        }
        // This really is a last resort.
        $o = '';
        $chars = 'abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+{}|":<>?\'\\';
        $l = strlen($chars);
        while ($a--) {
            $o .= substr($chars, rand(0, $l), 1);
        }

        return md5($o);
    }
}
