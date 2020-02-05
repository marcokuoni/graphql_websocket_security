<?php

namespace Helpers;

class Storage
{
    private $storage = [];

    public function has($key)
    {
        return array_key_exists($key, $this->storage);
    }

    public function get($key)
    {
        return $this->storage[$key];
    }

    public function set($key, $value)
    {
        $this->storage[$key] = $value;
    }

    public function remove($key)
    {
        unset($this->storage[$key]);
    }
}
