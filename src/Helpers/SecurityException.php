<?php

namespace Helpers;

use GraphQL\Error\ClientAware;

class SecurityException extends \Exception implements ClientAware
{
    public function isClientSafe()
    {
        return true;
    }

    public function getCategory()
    {
        return 'SecurityException';
    }
}