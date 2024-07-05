<?php declare(strict_types=1);

namespace PhilippR\Atk4\UserAuth;

use Atk4\Core\Exception;

class NoLoggedInUserException extends Exception
{
    protected $message = "No logged in user available";
}