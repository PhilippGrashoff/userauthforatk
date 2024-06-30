<?php

namespace PhilippR\Atk4\UserAuth\Tests\TestModels;

use Atk4\Data\Model;

class SomeOtherUserClass extends Model
{
    public $table = 'some_other_user_class';

    protected function init(): void
    {
        parent::init();
        $this->addField('username');
        $this->addField('password');
    }
}