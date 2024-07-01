<?php

namespace PhilippR\Atk4\UserAuth\Tests;

use Atk4\Data\Persistence\Sql;
use Atk4\Data\Schema\TestCase;
use PhilippR\Atk4\UserAuth\Auth;
use PhilippR\Atk4\UserAuth\InvalidCredentialsException;
use PhilippR\Atk4\UserAuth\User;

/**
 * @runTestsInSeparateProcesses
 */
class UserTest extends TestCase
{

    protected function setUp(): void
    {
        parent::setUp();
        $this->db = new Sql('sqlite::memory:');
        $this->createMigrator(new User($this->db))->create();
    }


    public function testSetPassword(): void
    {

    }

    public function testLastLoginTimeStoredOnLogin(): void
    {
        
    }

    public function testFailedLoginIncrease(): void
    {
        $user = $this->getTestUser();
        self::assertEquals(0, $user->get('failed_logins'));
        $this->makeFailedLogin($user);
        $user->reload();
        self::assertEquals(1, $user->get('failed_logins'));
    }

    public function testGetRemainingLogins(): void
    {
        $user = $this->getTestUser();
        self::assertEquals(10, $user->getRemainingLogins());
        $this->makeFailedLogin($user);
        $user->reload();
        self::assertEquals(9, $user->getRemainingLogins());
        $helper = \Closure::bind(static function () use ($user) {
            $user->maxFailedLogins = 1;
        }, null, $user);
        $helper();
        self::assertEquals(0, $user->getRemainingLogins());
    }

    public function testSetFailedLoginsToZeroOnSuccessfulLogin(): void
    {
        $user = $this->getTestUser();
        $this->makeFailedLogin($user);
        $user->reload();
        self::assertEquals(1, $user->get('failed_logins'));
        Auth::getInstance()->login($user->getModel(), $user->get('username'), 'somepassword');
        $user->reload();
        self::assertEquals(0, $user->get('failed_logins'));
    }

    public function testUserNameUnique(): void
    {
        $user = (new User($this->db))->createEntity();
        $user->set('username', 'ABC');
        $user->save();

        $user2 = (new User($this->db))->createEntity();
        $user2->set('username', 'ABC');
        self::expectExceptionMessage('The username is already in use, please select another one');
        $user2->save();
    }

    public function testExceptionSetNewPasswordOtherUserLoggedIn(): void
    {
        $user = $this->getTestUser();
        $user2 = $this->getTestUser('SomeOtherUserName');
        Auth::getInstance()->login($user->getModel(), $user->get('username'), 'somepassword');
        self::expectExceptionMessage('Password can only be changed by account owner');
        $user2->setNewPassword('ggg', 'ggg');
    }

    public function testExceptionSetNewPasswordOldPasswordWrong(): void
    {
        $user = $this->getTestUser();
        Auth::getInstance()->login($user->getModel(), $user->get('username'), 'somepassword');
        self::expectExceptionMessage('The old password is incorrect');
        $user->setNewPassword('ggg', 'ggg', true, 'falseoldpassword');
    }

    public function testExceptionSetNewPasswordsDoNotMatch(): void
    {
        $user = $this->getTestUser();
        Auth::getInstance()->login($user->getModel(), $user->get('username'), 'somepassword');
        self::expectExceptionMessage('The 2 new passwords do not match');
        $user->setNewPassword('gggfgfg', 'ggg', false);
    }

    public function testSetNewPassword(): void
    {
        $user = $this->getTestUser();
        Auth::getInstance()->login($user->getModel(), $user->get('username'), 'somepassword');
        $user->setNewPassword('someNewPassword', 'someNewPassword', false);
        self::assertTrue($user->getField('password')->verifyPassword($user, 'someNewPassword'));
    }

    protected function getTestUser(string $username = 'somename', string $password = 'somepassword'): User
    {
        $user = (new User($this->db))->createEntity();
        $user->set('username', $username);
        $user->getField('password')->setPassword($user, $password);
        $user->save();

        return $user;
    }

    protected function makeFailedLogin(User $user): void
    {
        try {
            Auth::getInstance()->login($user->getModel(), $user->get('username'), 'someWrongPassword');
        } catch (InvalidCredentialsException $e) {
        }
    }
}