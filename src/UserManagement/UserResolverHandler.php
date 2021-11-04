<?php

namespace C5GraphQl\UserManagement;

use Concrete\Core\Support\Facade\Application as App;
use Doctrine\ORM\Query\ResultSetMappingBuilder;
use Doctrine\ORM\Query\ResultSetMapping;
use Concrete\Core\Support\Facade\Config;
use Concrete5GraphqlWebsocket\Helpers\HasAccess;
use Concrete\Core\User\UserInfoRepository;
use function Siler\{array_get_arr};

use C5GraphQl\UserManagement\User;
use Concrete\Core\Entity\User\User as UserEntity;
use C5GraphQl\User\StatusService;
use Concrete\Core\Support\Facade\Log;
use Doctrine\ORM\EntityManagerInterface;
use Concrete\Core\User\Group\Group;

class UserResolverHandler
{
    public function createUser($root, $args, $context)
    {
        $sani = App::make('helper/security');
        $reCaptchaToken = $sani->sanitizeString($args['reCaptchaToken']);
        $adminArray = Config::get('concrete5_graphql_websocket_security::graphql_jwt.adminArray');

        if (!is_array($adminArray)) {
            $adminArray = ['/Administrators'];
        }

        $ip_service = App::make('ip');
        if ($ip_service->isBlacklisted()) {
            Log::addInfo('IP Blacklisted');
            throw new \Exception($ip_service->getErrorMessage());
        }

        if (!Config::get('concrete.user.registration.enabled') && !HasAccess::checkByGroup($context, $adminArray)) {
            Log::addInfo('Not allowed to create user');
            throw new UserManagementException('not_allowed');
        } elseif (!HasAccess::checkByGroup($context, $adminArray)) {
            if (Config::get('concrete.user.registration.captcha')) {
                $captcha = App::make(\Helpers\GoogleRecaptchaCheck::class);
                if (!$captcha->check($reCaptchaToken, 'signup')) {
                    Log::addInfo('create user captcha not valid');
                    throw new UserManagementException('unknown');
                }
            }
        }

        try {
            $username = $sani->sanitizeString($args['username']);
            $email = $sani->sanitizeString($args['email']);
            $password = $sani->sanitizeString($args['password']);
            $userLocale = $sani->sanitizeString($args['userLocale']);
            $avatar = $args['avatar'] ? array_get_arr($args, 'avatar') : null;
            $removeAvatar = (bool) $args['removeAvatar'];
            $validationUrl = $sani->sanitizeURL($args['validationUrl']);
            $displayName = $sani->sanitizeString($args['displayName']);
            $groups = $args['groups'];
            //check for existing user
            $ui = App::make(UserInfoRepository::class)->getByEmail($email);
            $pwHasher = App::make(\Concrete\Core\Encryption\PasswordHasher::class);
            $user = App::make(User::class);
            if (is_object($ui) && ($pwHasher->checkPassword($password, $ui->getUserPassword()) || HasAccess::checkByGroup($context, $adminArray))) {
                $userInfo = App::make(UserInfoRepository::class)->getByName($ui->getUserName());

                if (!$userInfo) {
                    Log::addInfo('Existing user not found: ' . $username);
                    Log::addInfo('Existing user not found');
                    throw new UserManagementException('user_not_found');
                }

                $result = $user->update($userInfo, $email, $validationUrl, $userLocale, $groups);
                return json_decode(json_encode($result));
            }

            //create user
            $result = $user->create($email, $password, $username, $validationUrl, $userLocale, $avatar, $removeAvatar, $groups, $displayName);
            return json_decode(json_encode($result));
        } catch (\Exception $e) {
            Log::addInfo('Couldnt create user: ' . $e->getMessage());
            throw new UserManagementException('unknown');
        }
    }

    public function updateUser($root, $args, $context)
    {
        $sani = App::make('helper/security');
        $ip_service = App::make('ip');
        $adminArray = Config::get('concrete5_graphql_websocket_security::graphql_jwt.adminArray');

        if (!is_array($adminArray)) {
            $adminArray = ['/Administrators'];
        }

        if ($ip_service->isBlacklisted()) {
            Log::addInfo('IP Blacklisted');
            throw new \Exception($ip_service->getErrorMessage());
        }

        try {
            $id = (int) $args['id'];
            $username = $sani->sanitizeString($args['username']);
            $contextUsername = $context['user']->uName;
            $contextId = (int)$context['user']->uID;
            $email = $sani->sanitizeString($args['email']);
            $password = $sani->sanitizeString($args['password']);
            $userLocale = $sani->sanitizeString($args['userLocale']);
            $avatar = $args['avatar'] ? array_get_arr($args, 'avatar') : null;
            $removeAvatar = (bool) $args['removeAvatar'];
            $displayName = $sani->sanitizeString($args['displayName']);
            $groups = $args['groups'];

            if (!HasAccess::checkByGroup($context, $adminArray) && $username !== $contextUsername && $id !== $contextId) {
                Log::addInfo('Not allowed to update user: ' . $contextUsername);
                throw new UserManagementException('unknown');
            }
            //check for existing user
            if ($username && $username !== '') {
                $userInfo = App::make(UserInfoRepository::class)->getByUserName($username);
            } else {
                $userInfo = App::make(UserInfoRepository::class)->getByID($id);
            }

            if (!$userInfo) {
                Log::addInfo('Existing user not found: ' . $username . $id);
                throw new UserManagementException('user_not_found');
            }

            //update user
            $user = App::make(User::class);
            $validationUrl = $sani->sanitizeURL($args['validationUrl']);
            $result = $user->update($userInfo, $email, $password, $validationUrl, $userLocale, $avatar, $removeAvatar, $groups, $displayName);
            return json_decode(json_encode($result));
        } catch (\Exception $e) {
            Log::addInfo('Couldnt update user: ' . $e->getMessage());
            throw new UserManagementException('unknown');
        }
    }

    public function sendValidationEmail($root, $args, $context)
    {

        $sani = App::make('helper/security');
        $reCaptchaToken = $sani->sanitizeString($args['reCaptchaToken']);
        $template = $args['template'] ? $sani->sanitizeString($args['template']) : null;

        $ip_service = App::make('ip');
        if ($ip_service->isBlacklisted()) {
            Log::addInfo('IP Blacklisted');
            throw new \Exception($ip_service->getErrorMessage());
        }

        $adminArray = Config::get('concrete5_graphql_websocket_security::graphql_jwt.adminArray');

        if (!is_array($adminArray)) {
            $adminArray = ['/Administrators'];
        }

        if (!HasAccess::checkByGroup($context, $adminArray)) {
            $captcha = App::make(\Helpers\GoogleRecaptchaCheck::class);
            if (!$captcha->check($reCaptchaToken, 'validationEmail')) {
                Log::addInfo('send validation captcha not valid');
                throw new UserManagementException('unknown');
            }
        }

        $id = (int) $args['id'];
        $uName = $sani->sanitizeString($args['uName']);
        $validationUrl = $sani->sanitizeURL($args['validationUrl']);
        if ($uName && $uName !== '') {
            $userInfo = App::make(UserInfoRepository::class)->getByUserName($uName);
        } else {
            $userInfo = App::make(UserInfoRepository::class)->getByID($id);
        }
        if (is_object($userInfo) && !$userInfo->isError()) {
            //send validation email
            App::make(StatusService::class)->sendEmailValidation($userInfo, $validationUrl, $template);
            return true;
        } else {
            Log::addInfo('Couldnt send validation email to ' . $uName . $id);
            throw new UserManagementException('unknown');
        }
    }

    public function validateEmail($root, $args, $context)
    {
        $sani = App::make('helper/security');
        $token = $sani->sanitizeString($args['token']);
        $reCaptchaToken = $sani->sanitizeString($args['reCaptchaToken']);

        $captcha = App::make(\Helpers\GoogleRecaptchaCheck::class);
        if (isset($reCaptchaToken) && is_string($reCaptchaToken) && ($reCaptchaToken !== '') && !$captcha->check($reCaptchaToken, 'validateEmail')) {
            Log::addInfo('validate email captcha not valid');
            throw new UserManagementException('unknown');
        }

        if (!isset($token)) {
            Log::addInfo('token not set');
            throw new UserManagementException('unknown');
        }

        $ui = App::make(UserInfoRepository::class)->getByValidationHash($token, false);
        if ($ui) {
            $ui->markValidated();
            // $this->set('uEmail', $ui->getUserEmail());
            // if ($ui->triggerActivate('register_activate', USER_SUPER_ID)) {
            //     $mode = '';
            // } else {
            //     $mode = 'workflow';
            // }
            // $this->redirect('/login/callback/concrete', 'email_validated', $mode);
            return true;
        }

        return false;
    }

    public function getDisplayName($root, $args, $context)
    {
        $sani = App::make('helper/security');
        $ip_service = App::make('ip');
        $appManagerArray = Config::get('concrete5_graphql_websocket_security::graphql_jwt.appManagerArray');

        if (!is_array($appManagerArray)) {
            $appManagerArray = ['/Administrators'];
        }

        if ($ip_service->isBlacklisted()) {
            Log::addInfo('IP Blacklisted');
            throw new \Exception($ip_service->getErrorMessage());
        }

        try {
            $username = $sani->sanitizeString($args['username']);
            $id = (int)$args['id'];
            $contextUsername = $context['user']->uName;
            $contextId = (int)$context['user']->uID;

            if ($contextUsername === '' && $contextId <= 0) {
                Log::addInfo('Not allowed to get display name: ' . $contextUsername);
                throw new UserManagementException('unknown');
            }
            //check for existing user
            if ($username) {
                $userInfo = App::make(UserInfoRepository::class)->getByName($username);
            } else {
                $userInfo = App::make(UserInfoRepository::class)->getByID($id);
            }

            if (!$userInfo) {
                Log::addInfo('Existing user not found: ' . $username . $id);
                throw new UserManagementException('user_not_found');
            }

            try {
                $displayName = ($userInfo->getAttribute("app_display_name") !== null) ? $userInfo->getAttribute("app_display_name") : '';
            } catch (\Exception $e) {
                Log::addInfo('Couldnt get display name: ' . $e->getMessage());
            }

            return $displayName;
        } catch (\Exception $e) {
            Log::addInfo('Couldnt get display name: ' . $e->getMessage());
            throw new UserManagementException('unknown');
        }
    }

    public function getUser($root, $args, $context)
    {
        $sani = App::make('helper/security');
        $ip_service = App::make('ip');
        $appManagerArray = Config::get('concrete5_graphql_websocket_security::graphql_jwt.appManagerArray');

        if (!is_array($appManagerArray)) {
            $appManagerArray = ['/Administrators'];
        }

        if ($ip_service->isBlacklisted()) {
            Log::addInfo('IP Blacklisted');
            throw new \Exception($ip_service->getErrorMessage());
        }

        try {
            $username = $sani->sanitizeString($args['username']);
            $id = (int)$args['id'];
            $contextUsername = $context['user']->uName;
            $contextId = (int)$context['user']->uID;

            if (!HasAccess::checkByGroup($context, $appManagerArray) && $username !== $contextUsername && $id !== $contextId) {
                Log::addInfo('Not allowed to get user: ' . $contextUsername);
                throw new UserManagementException('unknown');
            }
            //check for existing user
            if ($username) {
                $userInfo = App::make(UserInfoRepository::class)->getByName($username);
            } else {
                $userInfo = App::make(UserInfoRepository::class)->getByID($id);
            }

            if (!$userInfo) {
                Log::addInfo('Existing user not found: ' . $username . $id);
                throw new UserManagementException('user_not_found');
            }

            try {
                $displayName = ($userInfo->getAttribute("app_display_name") !== null) ? $userInfo->getAttribute("app_display_name") : '';
            } catch (\Exception $e) {
                Log::addInfo('Couldnt get display name: ' . $e->getMessage());
            }

            $uo = $userInfo->getUserObject();
            return [
                'id' => $userInfo->getUserID(),
                "uID" => $userInfo->getUserID(),
                'uName' => $userInfo->getUserName(),
                'uEmail' => $userInfo->getUserEmail(),
                "uDefaultLanguage" => $userInfo->getUserDefaultLanguage(),
                "uAvatar" => $userInfo->getUserAvatar()->getPath(),
                "displayName" => $displayName,
                "uGroupsPath" => is_array($uo->getUserGroupObjects()) ? array_map(function ($item) {
                    return $item->getGroupPath();
                }, $uo->getUserGroupObjects()) : [],
            ];
        } catch (\Exception $e) {
            Log::addInfo('Couldnt get user: ' . $e->getMessage());
            throw new UserManagementException('unknown');
        }
    }

    public function getUsers($root, $args, $context)
    {
        $ip_service = App::make('ip');
        $appManagerArray = Config::get('concrete5_graphql_websocket_security::graphql_jwt.appManagerArray');

        if (!is_array($appManagerArray)) {
            $appManagerArray = ['/Administrators'];
        }

        if ($ip_service->isBlacklisted()) {
            Log::addInfo('IP Blacklisted');
            throw new \Exception($ip_service->getErrorMessage());
        }

        try {
            $cursor = $args['cursor'];
            $offset = (int) $cursor['offset'];
            $pageSize = (int) $cursor['pageSize'];
            $sorted = $cursor['sorted'];
            $filtered = $cursor['filtered'];
            $contextUsername = $context['user']->uName;

            if (!HasAccess::checkByGroup($context, $appManagerArray)) {
                Log::addInfo('Not allowed to get  users: ' . $contextUsername);
                throw new UserManagementException('unknown');
            }

            $entityManager = App::make(EntityManagerInterface::class);
            $nativeQuery = ' FROM Users u';
            $whereQuery = '';
            $orderQuery = '';
            $rsm = new ResultSetMappingBuilder($entityManager);
            $rsm->addRootEntityFromClassMetadata(UserEntity::class, 'u');

            if ($filtered !== null && count($filtered) > 0) {
                $counter = 1;
                foreach ($filtered as $filter) {
                    switch ($filter['id']) {
                        case 'uID':
                            if ($whereQuery === '') {
                                $whereQuery .= ' WHERE ';
                            } else {
                                $whereQuery .= ' OR ';
                            }
                            $whereQuery .= 'u.uID = ' . $filter['value'];
                            break;
                        case 'uGroupsPath':
                            $groups = [];
                            $uGroupsPaths = explode(',', $filter['value']);
                            foreach ($uGroupsPaths as $uGroupsPath) {
                                $group = Group::getByPath($uGroupsPath);
                                if ($group) {
                                    $groups[] = $group->getGroupID();
                                }
                            }

                            $nativeQuery .= ' left join UserGroups ug on ug.uID = u.uID';

                            if ($whereQuery === '') {
                                $whereQuery .= ' WHERE ';
                            } else {
                                $whereQuery .= ' AND ';
                            }

                            if (count($groups) > 0) {
                                $whereQuery .= ' ug.gID IN (';
                                $whereQuery .= join(', ', $groups);
                                $whereQuery .= ')';
                            } else {
                                $whereQuery .= ' ug.gID is null';
                            }
                            break;
                        default:
                            if ($whereQuery === '') {
                                $whereQuery .= ' WHERE ';
                            } else {
                                $whereQuery .= ' AND ';
                            }
                            $whereQuery .= 'u.' . $filter['id'] . ' LIKE %' . $filter['value'] . '%';
                    }
                    $counter++;
                }
            }

            if ($sorted !== null && count($sorted) > 0) {
                foreach ($sorted as $sort) {
                    if ($orderQuery === '') {
                        $orderQuery .= ' ORDER BY ';
                    } else {
                        $orderQuery .= ', ';
                    }

                    $orderQuery .= 'u.' . $sort['id'] . ' ' . ((bool) $sort['asc'] ? 'ASC' : 'DESC');
                }
            } else {
                $orderQuery = ' ORDER BY u.uID';
            }

            $paginationQuery = ' LIMIT ' . $pageSize;
            $paginationQuery .= ' OFFSET ' . $offset;


            $query = $entityManager->createNativeQuery('SELECT *' . $nativeQuery . $whereQuery . $orderQuery . $paginationQuery, $rsm);
            $users = $query->getResult();

            $returnValue = array();
            $returnValue['items'] = array();
            foreach ($users as $user) {
                $userInfo = $user->getUserInfoObject();
                $uo = $userInfo->getUserObject();
                $displayName = ($userInfo->getAttribute("app_display_name") !== null) ? $userInfo->getAttribute("app_display_name") : '';
                $returnValue['items'][] = [
                    'id' => $userInfo->getUserID(),
                    "uID" => $userInfo->getUserID(),
                    'uName' => $userInfo->getUserName(),
                    'uEmail' => $userInfo->getUserEmail(),
                    "uDefaultLanguage" => $uo->getUserDefaultLanguage(),
                    "uAvatar" => $userInfo->getUserAvatar()->getPath(),
                    "displayName" => $displayName,
                    "uGroupsPath" => is_array($uo->getUserGroupObjects()) ? array_map(function ($item) {
                        return $item->getGroupPath();
                    }, $uo->getUserGroupObjects()) : [],
                ];
            }

            return $returnValue;
        } catch (\Exception $e) {
            Log::addInfo('Couldnt get users: ' . $e->getMessage());
            throw new UserManagementException('unknown');
        }
    }
}
