<?php

namespace Helpers;

defined('C5_EXECUTE') or die("Access Denied.");

use Concrete\Core\User\User;
use Concrete\Core\User\Group\Group;
use Concrete\Core\Error\UserMessageException;

class HasAccess
{
    public static function check($context, $groups = ['Administrators'])
    {
        $userId = $context['user']->uID;
        if ($userId && $userId > 0) {
            $user = User::getByUserID($userId);
            if ($user) {
                if ((int) $user->getUserID() === 1) {
                    return true;
                }

                foreach ($groups as $group) {
                    $groupItem = Group::getByName($group);
                    if ($groupItem && $user->inGroup($groupItem)) {
                        return true;
                    };
                }
            }
        }

        throw new UserMessageException('Access denied', 401);
    }
}
