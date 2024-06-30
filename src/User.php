<?php declare(strict_types=1);

namespace PhilippR\Atk4\UserAuth;

use Atk4\Data\Exception;
use Atk4\Data\Field\PasswordField;
use Atk4\Data\Model;
use PhilippR\Atk4\ModelTraits\UniqueFieldTrait;

class User extends Model
{

    use UniqueFieldTrait;

    public $table = 'user';
    public $caption = 'Benutzer';

    protected int $maxFailedLogins = 10;


    protected function init(): void
    {
        parent::init();
        $this->addfield(

            'name',
            [
                'type' => 'string',
            ]
        );
        $this->addfield(
            'username',
            [
                'type' => 'string',
                'ui' => ['form' => ['inputAttr' => ['autocomplete' => 'new-password']]]
            ]
        );
        $this->addfield(
            'password',
            [
                PasswordField::class,
                'system' => true,
                'ui' => ['form' => ['inputAttr' => ['autocomplete' => 'new-password']]]
            ]
        );

        $this->addField(
            'failed_logins',
            [
                'type' => 'integer',
                'caption' => 'Invalid login attempts since last login',
                'default' => 0,
                'system' => true,
            ]
        );

        $this->addField(
            'last_login',
            [
                'type' => 'datetime',
                'system' => true,
            ]
        );

        $this->onHook(
            Model::HOOK_BEFORE_SAVE,
            function (self $userEntity) {
                if (
                    $userEntity->get('username')
                    && !$userEntity->isFieldUnique('username')
                ) {
                    throw new Exception('The username is already in use, please select another one');
                }
            }
        );


        //disallow login attempt if there were too many failed logins since last login
        $this->onHook(
            Auth::HOOK_BEFORE_LOGIN,
            function ($userEntity) {
                if ($userEntity->get('failed_logins') >= $this->maxFailedLogins) {
                    throw new Exception('Too many login attempts since last failed logins');
                }
            }
        );

        //reset failed logins to zero on successful login; store last login time
        $this->onHook(
            Auth::HOOK_LOGGED_IN,
            function ($userEntity) {
                $userEntity->set('failed_logins', 0);
                $userEntity->set('last_login', new \DateTime());
                $userEntity->save();
            }
        );

        //increase failed login counter by 1 in case of failed login attempt
        $this->onHook(
            Auth::HOOK_BAD_LOGIN,
            function ($userEntity) {
                $userEntity->set('failed_logins', $userEntity->get('failed_logins') + 1);
                $userEntity->save();
            }
        );
    }

    public function setNewPassword(
        string $newPassword1,
        string $newPassword2,
        bool $checkOldPassword = true,
        string $oldPassword = ''
    ): void {
        //other user than logged-in user tries saving?
        if (Auth::getLoggedInUser()->getId() !== $this->getId()) {
            throw new Exception('Password can only be changed by account owner');
        }

        //old password entered needs to fit saved one
        if (
            $checkOldPassword
            && !$this->compare('password', $oldPassword)
        ) {
            throw new Exception('The old password is incorrect');
        }

        //new passwords need to match
        if ($newPassword1 !== $newPassword2) {
            throw new Exception('The 2 passwords do not match');
        }

        $this->set('password', $newPassword1);
    }

    /*
    public function resetPassword(
        string $tokenString,
        string $newPassword1,
        string $newPassword2
    ): void {
        //new passwords need to match
        if ($newPassword1 !== $newPassword2) {
            throw new Exception('The 2 passwords do not match');
        }

        $token = Token::loadTokenForEntity($this, $tokenString);
        $this->set('password', $newPassword1);
        $this->save();
        $token->delete();
    }*/
}