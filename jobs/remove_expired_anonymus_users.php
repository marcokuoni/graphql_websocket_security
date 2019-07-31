<?php
namespace Concrete\Package\Concrete5GraphqlWebsocketSecurity\Job;

use \Concrete\Core\Job\Job as AbstractJob;
use Doctrine\ORM\EntityManagerInterface;
use Entity\AnonymusUser as AnonymusUserEntity;
use Concrete\Core\Support\Facade\Application as App;

class RemoveExpiredAnonymusUsers extends AbstractJob
{

    public function getJobName()
    {
        return t("Remove expired anonymus users.");
    }

    public function getJobDescription()
    {
        return t("Will remove all anonymus users with an expired refresh token.");
    }

    public function run()
    {
        $entityManager = App::make(EntityManagerInterface::class);
        $deletedUser = $entityManager->createQueryBuilder()
        ->delete(AnonymusUserEntity::class, 'r')
        ->where('r.uGraphqlJwtRefreshTokenExpires < :current_time')
        ->setParameter('current_time', time())
        ->getQuery()->execute();

        return t('Deleted anonymus users') . ': ' . $deletedUser;
    }
}
