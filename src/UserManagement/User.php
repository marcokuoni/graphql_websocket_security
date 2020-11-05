<?php

namespace C5GraphQl\UserManagement;

use Concrete\Core\Support\Facade\Application as App;
use Concrete\Core\Support\Facade\Config;
use Concrete\Core\User\User as ConcreteUser;
use Concrete\Core\User\Group\Group;
use Concrete\Core\Localization\Localization;
use Doctrine\ORM\EntityManagerInterface;
use Concrete\Core\User\UserInfoRepository;
use Concrete\Core\Validator\String\EmailValidator;

use C5GraphQl\User\StatusService;

class User
{

    /**
     * @param EntityManagerInterface $entityManager
     */
    public function __construct(EntityManagerInterface $entityManager)
    {
        $this->entityManager = $entityManager;
    }

    public function create($email, $password, $username = null, $validationUrl = null, $userLocale = null, $groups = null)
    {
        $validationErrors = App::make('helper/validation/error');

        $result = [
            'result' => null,
            'validationErrors' => []
        ];

        try {
            App::make('validator/user/email')->isValid($email, $validationErrors);
            App::make('validator/password')->isValid($password, $validationErrors);

            if ($username) {
                $username = trim($username);
                $username = preg_replace('/ +/', ' ', $username);
                App::make('validator/user/name')->isValid($username, $validationErrors);
            } else {
                $userService = App::make(\Concrete\Core\Application\Service\User::class);
                $username = $userService->generateUsernameFromEmail($email);
            }

            if (!$validationErrors->has()) {
                $data = [
                    'uName' => $username,
                    'uEmail' => $email,
                    'uPassword' => $password
                ];
                //creates a user with uIsValidated = 0 if email validation is on
                $newUser = App::make('user/registration')->createFromPublicRegistration($data);
                $userInfo = App::make(UserInfoRepository::class)->getByName($username);
                $entity = $userInfo->getEntityObject();

                //send validation email
                if (Config::get('concrete.user.registration.validate_email')) {
                    App::make(StatusService::class)->sendEmailValidation($newUser, $validationUrl);
                }

                $this->updateLocale($entity, $userLocale, $validationErrors);
                $this->updateGroups($userInfo, $groups, $validationErrors);


                $result['result'] = ['uEmail' => $newUser->getUserEmail(), 'uName' => $newUser->getUserName()];
                return $result;
            } else {
                foreach ($validationErrors->getList() as $value) {
                    $result['validationErrors'][] = $value->getMessage();
                    return $result;
                }
            }
        } catch (\Exception $e) {
            throw $e;
        }
    }

    public function update($userInfo, $email = null, $validationUrl = null, $userLocale = null, $groups = null)
    {
        $validationErrors = App::make('helper/validation/error');

        $result = [
            'result' => null,
            'validationErrors' => []
        ];

        try {
            if ($email !== '') {
                App::make(EmailValidator::class)->isValid($email, $validationErrors);
            }

            if (!$validationErrors->has()) {
                $entity = $userInfo->getEntityObject();

                if ($email && $email !== '' && Config::get('concrete.user.registration.validate_email')) {
                    $entity->setUserIsValidated(0);
                    $entity->setUserEmail($email);

                    $this->entityManager->persist($entity);
                    $this->entityManager->flush();
                    App::make(StatusService::class)->sendEmailValidation($userInfo, $validationUrl);
                }

                $this->updateLocale($entity, $userLocale, $validationErrors);
                $this->updateGroups($userInfo, $groups, $validationErrors);

                $result['result'] = ['uEmail' => $userInfo->getUserEmail(), 'uName' => $userInfo->getUserName()];

                foreach ($validationErrors->getList() as $value) {
                    $result['validationErrors'][] = $value->getMessage();
                }

                return $result;
            } else {
                foreach ($validationErrors->getList() as $value) {
                    $result['validationErrors'][] = $value->getMessage();
                    return $result;
                }
            }
        } catch (\Exception $e) {
            throw $e;
        }
    }

    private function updateLocale(&$entity, &$userLocale, &$validationErrors)
    {
        if (is_string($userLocale) && ($userLocale !== '') && Config::get('concrete.i18n.choose_language_login')) {
            if ($userLocale !== Localization::BASE_LOCALE) {
                $availableLocales = Localization::getAvailableInterfaceLanguages();
                if (!in_array($userLocale, $availableLocales)) {
                    $userLocale = '';
                    $validationErrors->add(t('New userLocale "%1$s" is not available.', $userLocale));
                }
            }
            if ($userLocale !== '') {
                if (Localization::activeLocale() !== $userLocale) {
                    Localization::changeLocale($userLocale);
                }
                $entity->setUserDefaultLanguage($userLocale);
                $this->entityManager->persist($entity);
                $this->entityManager->flush();
            }
        }
    }

    private function updateGroups(&$userInfo, &$groups, &$validationErrors)
    {
        if (is_array($groups)) {
            $uo = $userInfo->getUserObject();
            $currentUserGroups = $uo->getUserGroups();
            $currentUserGroupPaths = [];
            foreach ($currentUserGroups as $currentGroupID) {
                $currentGroup = Group::getByID($currentGroupID);
                $currentUserGroupPaths[] = $currentGroup->getGroupPath();
            }
            foreach ($groups as $group) {
                if ($group['task'] === 'ADD') {
                    if (!in_array($group['name'], $currentUserGroupPaths)) {
                        $g = Group::getByPath($group['name']);
                        if ($g) {
                            $uo->enterGroup($g);
                        } else {
                            $validationErrors->add(t('New Group "%1$s" is not existing.', $group['name']));
                        }
                    }
                } else {
                    if (in_array($group['name'], $currentUserGroupPaths)) {
                        $g = Group::getByPath($group['name']);
                        if ($g) {
                            $uo->exitGroup($g);
                        } else {
                            $validationErrors->add(t('New Group "%1$s" is not existing.', $group['name']));
                        }
                    }
                }
            }
        }
    }
}
