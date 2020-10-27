<?php

namespace C5GraphQl\UserManagement;

use GraphQL\Error\ClientAware;

class UserManagementException extends \Exception implements ClientAware
{
    public function isClientSafe()
    {
        return true;
    }

    public function getCategory()
    {
        return 'UserManagementException';
    }
}