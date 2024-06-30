<?php declare(strict_types=1);

namespace PhilippR\Atk4\UserAuth\Tests;

use Atk4\Data\Persistence\Sql;
use Atk4\Data\Schema\TestCase;
use PhilippR\Atk4\UserAuth\Auth;
use PhilippR\Atk4\UserAuth\InvalidCredentialsException;
use PhilippR\Atk4\UserAuth\Tests\TestModels\SomeOtherUserClass;
use PhilippR\Atk4\UserAuth\User;

/**
 * @runTestsInSeparateProcesses
 */
class AuthTest extends TestCase
{

    protected function setUp(): void
    {
        parent::setUp();
        $this->db = new Sql('sqlite::memory:');
        $this->createMigrator(new User($this->db))->create();
    }

    public function testLoginExceptionUserAlreadyLoggedIn(): void
    {
        $user1 = $this->getTestUser();
        $user2 = $this->getTestUser('someothername', 'someotherpassword');
        Auth::login(new User($this->db), $user1->get('username'), 'somepassword');
        self::expectExceptionMessage('A User is already logged in, logout prior to login!');
        Auth::login($user2, $user2->get('username'), 'someotherpassword');
    }

    public function testLoginExceptionWrongModelClassPassed(): void
    {
        $someOtherUser = new SomeOtherUserClass($this->db);
        self::expectExceptionMessage('Instance of wrong class passed. ' . Auth::$userModel . ' expected.');
        Auth::login($someOtherUser, '', '');
    }

    public function testLoginExceptionNoUserFound(): void
    {
        self::expectException(InvalidCredentialsException::class);
        Auth::login(new User($this->db), 'somenonexistantusername', '');
    }

    public function testLoginExceptionWrongPassword(): void
    {
        $user = $this->getTestUser();
        self::expectException(InvalidCredentialsException::class);
        Auth::login(new User($this->db), $user->get('username'), 'somewrongpassword');
    }

    public function testLoginSuccess(): void
    {
        $user = $this->getTestUser();
        Auth::login(new User($this->db), $user->get('username'), 'somepassword');
        self::assertSame($user->getId(), Auth::getLoggedInUser($this->db)->getId());
    }

    public function testGetLoggedInUserExceptionNoLoggedInUserAvaible(): void
    {
        self::expectExceptionMessage('No logged in user available');
        Auth::getLoggedInUser($this->db);
    }

    public function testLogout(): void
    {
        $user = $this->getTestUser();
        Auth::login(new User($this->db), $user->get('username'), 'somepassword');
        self::assertSame($user->getId(), Auth::getLoggedInUser($this->db)->getId());
        Auth::logout();
        self::expectExceptionMessage('No logged in user available');
        Auth::getLoggedInUser($this->db);
    }

    public function testDangerouslySetLoggedInUser(): void
    {
        $user = $this->getTestUser();
        Auth::dangerouslySetLoggedInUser($user);
        self::assertSame($user->getId(), Auth::getLoggedInUser($this->db)->getId());
    }

    public function testDangerouslySetLoggedInUserWithOverwrite(): void
    {
        $user1 = $this->getTestUser();
        $user2 = $this->getTestUser('someothername', 'someotherpassword');
        Auth::login(new User($this->db), $user1->get('username'), 'somepassword');
        self::assertSame($user1->getId(), Auth::getLoggedInUser($this->db)->getId());
        Auth::dangerouslySetLoggedInUser($user2, true);
        self::assertSame($user2->getId(), Auth::getLoggedInUser($this->db)->getId());
    }

    public function testDangerouslySetLoggedInUserOverwriteException(): void
    {
        $user1 = $this->getTestUser();
        $user2 = $this->getTestUser('someothername', 'someotherpassword');
        Auth::login(new User($this->db), $user1->get('username'), 'somepassword');
        self::expectExceptionMessage('Cannot overwrite logged in user.');
        Auth::dangerouslySetLoggedInUser($user2);
    }

    public function testDangerouslySetLoggedInUserExceptionWrongClass(): void
    {
        $this->createMigrator(new SomeOtherUserClass($this->db))->create();
        $someOtherUser = (new SomeOtherUserClass($this->db))->createEntity();
        $someOtherUser->save();
        self::expectExceptionMessage('Instance of wrong class passed. ' . Auth::$userModel . ' expected.');
        Auth::dangerouslySetLoggedInUser($someOtherUser);
    }

    protected function getTestUser(string $username = 'somename', string $password = 'somepassword'): User
    {
        $user = (new User($this->db))->createEntity();
        $user->set('username', $username);
        $user->getField('password')->setPassword($user, $password);
        $user->save();

        return $user;
    }
}
