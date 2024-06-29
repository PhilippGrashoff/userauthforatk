<?php declare(strict_types=1);

namespace PhilippR\Atk4\UserAuth;

use Atk4\Core\Exception;
use Atk4\Core\HookTrait;
use Atk4\Data\Field\PasswordField;
use Atk4\Data\Model;

class Auth
{
    use HookTrait;

    public const HOOK_LOGGED_IN = self::class . '@loggedIn';
    public const HOOK_BAD_LOGIN = self::class . '@badLogin';

    /** @var string Which field to look up user by. */
    public static string $fieldLogin = 'name';

    /** @var string Password to be verified when authenticating. */
    public static string $fieldPassword = 'password';

    /** @var string The key for $_SESSION array to store the logged-in user in */
    protected static string $sessionKeyForUser = '__atk_user';

    protected static string $userModel = User::class;

    public static function login(Model $userModel, string $username, string $password): void
    {
        // first logout
        self::logout();

        $userModel->assertIsModel();
        //use tryLoadBy and throw generic exception to avoid username guessing
        $userEntity = $userModel->tryLoadBy(self::$fieldLogin, $username);
        if ($userEntity === null) {
            throw new Exception('Invalid username or Password');
        }
        // verify if the password matches
        $passwordField = PasswordField::assertInstanceOf($userEntity->getField(self::$fieldPassword));
        if ($passwordField->verifyPassword($userEntity, $password)) {
            $userEntity->hook(self::HOOK_LOGGED_IN, [$userEntity]);
            $_SESSION[self::$sessionKeyForUser] = clone $userEntity;
        } else {
            $userEntity->hook(self::HOOK_BAD_LOGIN, [$userEntity]);
            throw new Exception('Invalid username or Password');
        }
    }

    public static function logout(): void
    {
        session_destroy();
        session_start();
        session_regenerate_id();
        $_SESSION[self::$sessionKeyForUser] = null;
    }

    public static function getLoggedInUser(): Model
    {
        //load user from session cache
        if (!isset($_SESSION[self::$sessionKeyForUser]) || $_SESSION[self::$sessionKeyForUser] === null) {
            throw new Exception('No logged in user available');
        }
        //this should never happen unless something really went wrong
        if (!$_SESSION[self::$sessionKeyForUser] instanceof self::$userModel) {
            throw new Exception('Instance of wrong class stored in session, ' . self::$userModel . ' expected.');
        }
        return $_SESSION[self::$sessionKeyForUser];
    }

    /**
     * This method should not be used unless for special occations where a user needs to be set, e.g.
     * - a script run by a cronjob
     * - an API script where the API key points to a user
     *
     * @param Model $userEntity
     * @param bool $disallowOverwrite
     * @return void
     * @throws Exception
     * @throws \Atk4\Data\Exception
     */
    public static function dangerouslySetLoggedInUser(Model $userEntity, bool $disallowOverwrite = true): void
    {
        $userEntity->assertIsLoaded();
        if (
            $disallowOverwrite
            && isset($_SESSION[self::$sessionKeyForUser])
            && $_SESSION[self::$sessionKeyForUser] !== null
        ) {
            throw new Exception('Cannot overwrite logged in user.');
        }
        if (!$userEntity instanceof self::$userModel) {
            throw new Exception('Instance of wrong class passed. ' . self::$userModel . ' expected.');
        }
        $_SESSION[self::$sessionKeyForUser] = clone $userEntity;
    }
}