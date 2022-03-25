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
                <li><?= t('Authorize secret, used to build a new token out of a refresh token [Text]') ?></li>
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
            <label class="launch-tooltip" for="auth_secret_key" data-placement="right" title="<?= t('Secret Key for JWT signing, will be just visible for super user. If you change it, all token getting invalidated. Placeholder for random key ca be copy/paste') ?>"><?= t('Secret Key') ?></label>
            <div class="form-group">
                <div class="form-group">
                    <?= $form->text('auth_secret_key', (string) $auth_secret_key !== '' ? (string) $auth_secret_key : t('You are not super user and not able to change or view the secret key'), ['placeholder' => bin2hex(random_bytes(32))]) ?>
                </div>
            </div>
        </div>
        <div class="form-group">
            <label class="launch-tooltip" for="auth_secret_key" data-placement="right" title="<?= t('Secret Key for JWT signing, will be just visible for super user. If you change it, all token getting invalidated. Placeholder for random key ca be copy/paste') ?>"><?= t('Refresh Secret Key') ?></label>
            <div class="form-group">
                <div class="form-group">
                    <?= $form->text('auth_refresh_secret_key', (string) $auth_refresh_secret_key !== '' ? (string) $auth_refresh_secret_key : t('You are not super user and not able to change or view the secret key'), ['placeholder' => bin2hex(random_bytes(32))]) ?>
                </div>
            </div>
        </div>
        <div class="form-group">
            <label class="launch-tooltip" for="corsOrigins" data-placement="right" title="<?= t('Allowed cors origin') ?>"><?= t('CORS Origins') ?></label>
            <div class="form-group">
                <div class="form-group">
                    <?= $form->text('corsOrigins', (string) $corsOrigins !== '' ? (string) $corsOrigins : t('You are not super user and not able to change or view the secret key'), ['placeholder' => $_SERVER['HTTP_ORIGIN']]) ?>
                </div>
            </div>
        </div>

        <div class="form-group">
            <label class="launch-tooltip" for="auth_expire" data-placement="right" title="<?= t('A standard token will expire after how long? Default would be after 30 sec') ?>"><?= t('Token Expire [s]') ?></label>
            <div class="form-group">
                <div class="form-group">
                    <?= $form->text('auth_expire', (int) $auth_expire > 0 ? (int) $auth_expire : '', ['placeholder' => 30]) ?>
                </div>
            </div>
        </div>

        <div class="form-group">
            <label class="launch-tooltip" for="auth_refresh_expire" data-placement="right" title="<?= t('A refresh token will expire after how long? Default would be after 7200 sec') ?>"><?= t('Refresh Token Expire [s]') ?></label>
            <div class="form-group">
                <div class="form-group">
                    <?= $form->text('auth_refresh_expire', (int) $auth_refresh_expire > 0 ? (int) $auth_refresh_expire : '', ['placeholder' => 7200]) ?>
                </div>
            </div>
        </div>
    </fieldset>
    <fieldset>
        <legend><?= t('Refresh Cookie Settings') ?></legend>
        <div class="form-group">
            <label class="launch-tooltip" for="cookie_name" data-placement="right" title="<?= t('How is the refresh cookie named. Use a not obviously name') ?>"><?= t('Cookie Name') ?></label>
            <div class="form-group">
                <div class="form-group">
                    <?= $form->text('cookie_name', (string) $cookie_name ?? '', ['placeholder' => '1dW4ed4cDe4dfdw45']) ?>
                </div>
            </div>
        </div>

        <div class="form-group">
            <label class="launch-tooltip" for="cookie_domain" data-placement="right" title="<?= t('Defines the host to which the cookie will be sent') ?>"><?= t('Cookie Domain') ?></label>
            <div class="form-group">
                <div class="form-group">
                    <?= $form->text('cookie_domain', (string) $cookie_domain ?? '', ['placeholder' => $_SERVER['HTTP_HOST']]) ?>
                </div>
            </div>
        </div>

        <div class="form-group">
            <label class="launch-tooltip" for="cookie_path" data-placement="right" title="<?= t('Indicates the path that must exist in the requested URL for the browser to send the Cookie header') ?>"><?= t('Cookie Path') ?></label>
            <div class="form-group">
                <div class="form-group">
                    <?= $form->text('cookie_path', (string) $cookie_path ?? '', ['placeholder' => '/refresh_token']) ?>
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
        <div class="form-group" style="margin-top: 30px;">
            <label class="launch-tooltip" data-placement="right" title="<?= t('Declare if your cookie should be restricted to a first-party or same-site context') ?>"><?= t('Cookie SameSite') ?></label>
            <div class="radio">
                <label>
                    <?= $form->radio('cookie_same_site', 'Strict', $cookie_same_site === 'Strict') ?>
                    <span><?= t('Strict') ?></span>
                </label>
            </div>

            <div class="radio">
                <label>
                    <?= $form->radio('cookie_same_site', 'Lax', $cookie_same_site === 'Lax') ?>
                    <span><?= t('Lax') ?></span>
                </label>
            </div>

            <div class="radio">
                <label>
                    <?= $form->radio('cookie_same_site', 'None', $cookie_same_site === 'None') ?>
                    <span><?= t('None (Needs Secure true)') ?></span>
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