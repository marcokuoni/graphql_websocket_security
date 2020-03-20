<?php

use Concrete\Core\Support\Facade\Application as App;

/**
 * @var Concrete\Core\Form\Service\Form $form
 * @var Concrete\Core\Html\Service\Html $html
 * @var Concrete\Core\Page\View\PageView $this
 * @var Concrete\Core\Validation\CSRF\Token $token
 * @var Concrete\Core\Page\View\PageView $view
 * @var array $websocket_servers
 * @var bool $websocket_has_servers
 * @var bool $websocket_debug
 * @var bool $graphql_dev_mode
 * @var int $max_query_complexity
 * @var bool $query_complexity_analysis
 * @var int $max_query_depth
 * @var bool $limiting_query_depth
 * @var bool $disabling_introspection
 * @var string $logPath
 */

defined('C5_EXECUTE') or die('Access Denied.');


$dh = App::make(\Concrete\Core\Localization\Service\Date::class);

?>

<form method="post" id="entities-settings-form" action="<?= $view->action('update_entity_settings') ?>" style="position: relative">
    <?= $token->output('update_entity_settings') ?>
    <div class="help-block">
        <div>
            <p><?= t('The security packages adds different user Attributes') ?></p>
            <ul>
                <li><?= t('Authorize secret, used to buil a new token out of a refresh token [Text]') ?></li>
                <li><?= t('Authorize secret revoked, blocks the ability to create new tokens for a user [Boolean]') ?>
                </li>
                <li><?= t('Token not before, the tokens will just be valid after this time [Seconds]') ?></li>
                <li><?= t('Token expires, shows when the last token expires [Seconds, read only]') ?></li>
                <li><?= t('Refresh token expires, shows when the last refresh token expires [Seconds, read only]') ?>
                </li>
                <li><?= t('Last request, shows the last request of an user [Seconds, read only, check setting bellow]') ?>
                </li>
                <li><?= t('Last request IP, shows the last request IP of an user [Text, read only, check setting bellow]') ?>
                </li>
                <li><?= t('Last request agent, shows the last request agent of an user [Text, read only, check setting bellow]') ?>
                </li>
                <li><?= t('Last request timezone, shows the last request timezone of an user [Text, read only, check setting bellow]') ?>
                </li>
                <li><?= t('Last request language, shows the last request language of an user [Text, read only, check setting bellow]') ?>
                </li>
                <li><?= t('Request count, counts the user requests [Number, read only, check setting bellow]') ?></li>
            </ul>
        </div>
    </div>

    <fieldset>
        <legend><?= t('GraphQL Security Settings') ?></legend>
        <div class="form-group">
            <label class="launch-tooltip" for="auth_secret_key" data-placement="right" title="<?= t('Secret Key for JWT signing, will be just visible for super user. If you change it, all token getting invalidated') ?>"><?= t('Secret Key') ?></label>
            <div class="form-group">
                <div class="form-group">
                    <?= $form->text('auth_secret_key', (string) $auth_secret_key !== '' ? (string) $auth_secret_key : t('You are not super user and not able to change or view the secret key')) ?>
                </div>
            </div>
        </div>
        <div class="form-group">
            <label class="launch-tooltip" for="auth_secret_key" data-placement="right" title="<?= t('Secret Key for JWT signing, will be just visible for super user. If you change it, all token getting invalidated') ?>"><?= t('Refresh Secret Key') ?></label>
            <div class="form-group">
                <div class="form-group">
                    <?= $form->text('auth_refresh_secret_key', (string) $auth_refresh_secret_key !== '' ? (string) $auth_refresh_secret_key : t('You are not super user and not able to change or view the secret key')) ?>
                </div>
            </div>
        </div>

        <div class="form-group">
            <label class="launch-tooltip" for="auth_expire" data-placement="right" title="<?= t('A standard token will expire after how long? Default would be after 300 sec') ?>"><?= t('Token Expire [s]') ?></label>
            <div class="form-group">
                <div class="form-group">
                    <?= $form->text('auth_expire', (int) $auth_expire > 0 ? (int) $auth_expire : 300) ?>
                </div>
            </div>
        </div>

        <div class="form-group">
            <label class="launch-tooltip" for="auth_refresh_expire" data-placement="right" title="<?= t('A refresh token will expire after how long? Default would be after 86400 * 365 sec') ?>"><?= t('Refresh Token Expire [s]') ?></label>
            <div class="form-group">
                <div class="form-group">
                    <?= $form->text('auth_refresh_expire', (int) $auth_refresh_expire > 0 ? (int) $auth_refresh_expire : (86400 * 365)) ?>
                </div>
            </div>
        </div>

        <div class="form-group" style="margin-top: 30px;">
            <label class="launch-tooltip" data-placement="right" title="<?= t('Rejects all API requests as long as they do not have a valid token in it. So you need to send valid tokens with the initinal html request for the client application.') ?>"><?= t('API call just with valid token') ?></label>
            <div class="radio">
                <label>
                    <?= $form->radio('just_with_valid_token', 'yes', $just_with_valid_token) ?>
                    <span><?= t('On') ?></span>
                </label>
            </div>

            <div class="radio">
                <label>
                    <?= $form->radio('just_with_valid_token', 'no', !$just_with_valid_token) ?>
                    <span><?= t('Off, i know what i am doing') ?></span>
                </label>
            </div>
        </div>

        <div class="form-group" style="margin-top: 30px;">
            <label class="launch-tooltip" data-placement="right" title="<?= t('Logs the last request time, ip, agent, timezone, language and the request count to a concrete5 or anonymous user') ?>"><?= t('Log User Requests') ?></label>
            <div class="radio">
                <label>
                    <?= $form->radio('log_requests', 'yes', $log_requests) ?>
                    <span><?= t('On') ?></span>
                </label>
            </div>

            <div class="radio">
                <label>
                    <?= $form->radio('log_requests', 'no', !$log_requests) ?>
                    <span><?= t('Off') ?></span>
                </label>
            </div>
        </div>

        <div class="form-group" style="margin-top: 30px;">
            <label class="launch-tooltip" data-placement="right" title="<?= t('If the clients starts a request the token could expire during transaction, cause of latency. So we give him one second change to refresh his token') ?>"><?= t('One Time Auto Refresh') ?></label>
            <div class="radio">
                <label>
                    <?= $form->radio('one_time_auto_refresh', 'yes', $one_time_auto_refresh) ?>
                    <span><?= t('On') ?></span>
                </label>
            </div>

            <div class="radio">
                <label>
                    <?= $form->radio('one_time_auto_refresh', 'no', !$one_time_auto_refresh) ?>
                    <span><?= t('Off') ?></span>
                </label>
            </div>
        </div>
    </fieldset>
    <fieldset>
        <legend><?= t('Refresh Cookie Settings') ?></legend>
        <div class="form-group">
            <label class="launch-tooltip" for="cookie_name" data-placement="right" title="<?= t('How is the refresh cookie named. Use a not obviously name') ?>"><?= t('Cookie Name') ?></label>
            <div class="form-group">
                <div class="form-group">
                    <?= $form->text('cookie_name', (string) $cookie_name !== '' ? (string) $cookie_name : 'mainApp') ?>
                </div>
            </div>
        </div>

        <div class="form-group">
            <label class="launch-tooltip" for="cookie_lifetime" data-placement="right" title="<?= t('How long should the refresh token be valid? Default would be after 86400 * 365 sec') ?>"><?= t('Cookie Lifetime') ?></label>
            <div class="form-group">
                <div class="form-group">
                    <?= $form->text('cookie_lifetime', (string) $cookie_lifetime !== '' ? (int) $cookie_lifetime : (86400 * 365)) ?>
                </div>
            </div>
        </div>

        <div class="form-group">
            <label class="launch-tooltip" for="cookie_domain" data-placement="right" title="<?= t('The domain who can change the cookie') ?>"><?= t('Cookie Domain') ?></label>
            <div class="form-group">
                <div class="form-group">
                    <?= $form->text('cookie_domain', (string) $cookie_domain !== '' ? (string) $cookie_domain : '') ?>
                </div>
            </div>
        </div>

        <div class="form-group" style="margin-top: 30px;">
            <label class="launch-tooltip" data-placement="right" title="<?= t('Just https connection is accepted') ?>"><?= t('Cookie Secure') ?></label>
            <div class="radio">
                <label>
                    <?= $form->radio('cookie_secure', 'yes', $cookie_secure) ?>
                    <span><?= t('On') ?></span>
                </label>
            </div>

            <div class="radio">
                <label>
                    <?= $form->radio('cookie_secure', 'no', !$cookie_secure) ?>
                    <span><?= t('Off') ?></span>
                </label>
            </div>
        </div>
    </fieldset>

    <div class="ccm-dashboard-form-actions-wrapper">
        <div class="ccm-dashboard-form-actions">
            <button class="pull-right btn btn-primary" type="submit"><?= t('Save') ?></button>
        </div>
    </div>

</form>
</script>