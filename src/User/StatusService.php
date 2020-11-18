<?php
// namespace Concrete\Core\User;
namespace C5GraphQl\User;

use Concrete\Core\Application\Application;
use Concrete\Core\Mail\Service as MailService;
use Concrete\Core\Config\Repository\Repository;

class StatusService
{
    protected $application;
    protected $mh;
    protected $config;

    /**
     * StatusService constructor.
     * @param \Concrete\Core\Application\Application $application
     * @param \Concrete\Core\Mail\Service $mh
     * @param \Concrete\Core\Config\Repository\Repository $config
     */
    public function __construct(Application $application, MailService $mh, Repository $config)
    {
        $this->application = $application;
        $this->mh = $mh;
        $this->config = $config;
    }

    public function sendEmailValidation($user, $validationUrl)
    {
        if ($validationUrl !== '') {
            $uHash = $user->setupValidation();
            $fromEmail = (string) $this->config->get('concrete.email.validate_registration.address');
            if (strpos($fromEmail, '@')) {
                $fromName = (string) $this->config->get('concrete.email.validate_registration.name');
                if ($fromName === '') {
                    $fromName = t('Validate Email Address');
                }
                $this->mh->from($fromEmail, $fromName);
            }
            $this->mh->addParameter('uEmail', $user->getUserEmail());
            $this->mh->addParameter('uHash', $uHash);
            $this->mh->addParameter('uEmail', $user->getUserEmail());
            $this->mh->addParameter('site', tc('SiteName', $this->config->get('concrete.site')));
            $this->mh->addParameter('validationUrl', $validationUrl);
            $this->mh->to($user->getUserEmail());
            $this->mh->load('validate_user_email', 'concrete5_graphql_websocket_security');
            $this->mh->sendMail();
        }
    }
}
