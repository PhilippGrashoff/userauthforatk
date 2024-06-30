<?php declare(strict_types=1);

namespace PhilippR\Atk4\UserAuth;

use Atk4\Core\Exception;
use Atk4\Core\HookTrait;
use Atk4\Data\Field\PasswordField;
use Atk4\Data\Model;
use Atk4\Data\Persistence;

class Auth
{
    use HookTrait;

    public const HOOK_BEFORE_LOGIN = self::class . '@beforeLogin';
    public const HOOK_LOGGED_IN = self::class . '@loggedIn';
    public const HOOK_BAD_LOGIN = self::class . '@badLogin';

    /** @var string The key for $_SESSION array to store the logged-in user in */
    protected static string $sessionKeyForUser = '__atk_user';

    /** @var class-string|Model The user model class to check against */
    public static string $userModel = User::class;

    /**
     * @param Model $userModel
     * @param string $username
     * @param string $password
     * @param string $fieldUsername
     * @param string $fieldPassword
     * @return void
     * @throws Exception
     * @throws InvalidCredentialsException
     * @throws \Atk4\Data\Exception
     */
    public static function login(
        Model $userModel,
        string $username,
        string $password,
        string $fieldUsername = 'username',
        string $fieldPassword = 'password'
    ): void {
        //login should only be possible if no logged-in user is set!
        if (!empty($_SESSION[self::$sessionKeyForUser])) {
            throw new Exception('A User is already logged in, logout prior to login!');
        }
        $userModel->assertIsModel();
        if (!$userModel instanceof self::$userModel) {
            throw new Exception('Instance of wrong class passed. ' . self::$userModel . ' expected.');
        }

        //use tryLoadBy and throw generic exception to avoid username guessing
        $userEntity = $userModel->tryLoadBy($fieldUsername, $username);
        if ($userEntity === null) {
            throw new InvalidCredentialsException();
        }

        //can e.g. be used to check max. failed logins before another attempt
        $userEntity->hook(self::HOOK_BEFORE_LOGIN, [$userEntity]);

        // verify if the password matches
        $passwordField = PasswordField::assertInstanceOf($userEntity->getField($fieldPassword));
        if ($passwordField->verifyPassword($userEntity, $password)) {
            $userEntity->hook(self::HOOK_LOGGED_IN, [$userEntity]);
            $_SESSION[self::$sessionKeyForUser] = $userEntity->get();
        } else {
            $userEntity->hook(self::HOOK_BAD_LOGIN, [$userEntity]);
            throw new InvalidCredentialsException();
        }
    }

    /**
     * TODO: Which actions/function calls are really sensible here?
     *
     * @return void
     */
    public static function logout(): void
    {
        $_SESSION[self::$sessionKeyForUser] = null;
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_destroy();
        }
        session_start();
        session_regenerate_id();
    }

    /**
     * @param Persistence $persistence
     * @return Model
     * @throws Exception
     */
    public static function getLoggedInUser(Persistence $persistence): Model
    {
        $userEntity = (new self::$userModel($persistence))->createEntity();;
        //load user from session cache
        if (
            !isset($_SESSION[self::$sessionKeyForUser])
            || !isset($_SESSION[self::$sessionKeyForUser][$userEntity->idField])
        ) {
            throw new Exception('No logged in user available');
        }
        $userEntity->setMulti($_SESSION[self::$sessionKeyForUser]);

        return $userEntity;
    }

    /**
     * This method should not be used unless for special occasions where a user needs to be set, e.g.
     * - a script run by a cronjob
     * - an API script where the API key points to a user
     *
     * @param Model $userEntity
     * @param bool $allowOverwrite
     * @return void
     * @throws Exception
     * @throws \Atk4\Data\Exception
     */
    public static function dangerouslySetLoggedInUser(Model $userEntity, bool $allowOverwrite = false): void
    {
        $userEntity->assertIsLoaded();
        if (
            !$allowOverwrite
            && isset($_SESSION[self::$sessionKeyForUser])
            && isset($_SESSION[self::$sessionKeyForUser][$userEntity->idField])
        ) {
            throw new Exception('Cannot overwrite logged in user.');
        }
        if (!$userEntity instanceof self::$userModel) {
            throw new Exception('Instance of wrong class passed. ' . self::$userModel . ' expected.');
        }
        $_SESSION[self::$sessionKeyForUser] = $userEntity->get();
    }
}