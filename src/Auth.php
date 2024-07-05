<?php declare(strict_types=1);

namespace PhilippR\Atk4\UserAuth;

use Atk4\Core\Exception;
use Atk4\Core\HookTrait;
use Atk4\Data\Field\PasswordField;
use Atk4\Data\Model;
use Atk4\Data\Persistence;


/**
 * Singleton Pattern implementation taken from
 * https://github.com/DesignPatternsPHP/DesignPatternsPHP/blob/main/Creational/Singleton/Singleton.php
 */
class Auth
{
    use HookTrait;

    protected static ?Auth $instance = null;

    /** @var class-string|Model The user model class to check against */
    public static string $userModel = User::class;

    /** @var Model|null an instance of the logged-in user */
    protected ?Model $userEntity = null;

    public const HOOK_BEFORE_LOGIN = self::class . '@beforeLogin';
    public const HOOK_LOGGED_IN = self::class . '@loggedIn';
    public const HOOK_BAD_LOGIN = self::class . '@badLogin';

    /** @var string The key for $_SESSION array to store the logged-in user in */
    protected static string $sessionKeyForUser = '__atk_user';

    public static function getInstance(): Auth
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    /**
     * @codeCoverageIgnore;
     */
    protected function __construct()
    {
    }

    /**
     * @codeCoverageIgnore;
     */
    protected function __clone()
    {
    }

    /**
     * @codeCoverageIgnore;
     */
    public function __wakeup()
    {
        throw new Exception("Cannot unserialize singleton");
    }

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
    public function login(
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
            $this->userEntity = clone $userEntity;
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
    public function logout(): void
    {
        $_SESSION[self::$sessionKeyForUser] = null;
        $this->userEntity = null;
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_destroy();
        }
        session_start();
        session_regenerate_id();
    }

    /**
     * retrieve the login User
     *
     * @param Persistence $persistence
     * @return Model
     * @throws Exception
     */
    public function getUser(Persistence $persistence): Model
    {
        if ($this->userEntity) {
            return $this->userEntity;
        }
        $userEntity = (new self::$userModel($persistence))->createEntity();;
        //load user from session cache
        if (
            !isset($_SESSION[self::$sessionKeyForUser])
            || !isset($_SESSION[self::$sessionKeyForUser][$userEntity->idField])
        ) {
            throw new NoLoggedInUserException();
        }
        $userEntity->setMulti($_SESSION[self::$sessionKeyForUser]);
        $this->userEntity = $userEntity;
        return $this->userEntity;
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
    public function dangerouslySetLoggedInUser(Model $userEntity, bool $allowOverwrite = false): void
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
        $this->userEntity = $userEntity;
    }
}