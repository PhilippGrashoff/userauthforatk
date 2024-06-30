<?php declare(strict_types=1);

namespace PhilippR\Atk4\UserAuth;

use Atk4\Core\Exception;

class InvalidCredentialsException extends Exception
{

    protected $message = "Invalid username or password";
}