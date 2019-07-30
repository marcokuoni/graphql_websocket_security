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
            <label class="launch-tooltip" for="auth_expire" data-placement="right" title="<?= t('A standard token will expire after how long? Default would be after 300 sec') ?>"><?= t('Token Expire [s]') ?></label>
            <div class="form-group">
                <div class="form-group">
                    <?= $form->text('auth_expire', (int) $auth_expire > 0 ? (int) $auth_expire : 300) ?>
                </div>
            </div>
        </div>

        <div class="form-group" style="margin-top: 30px;">
            <label class="launch-tooltip" data-placement="right" title="<?= t('Log anonymus user in the database, you will see the table here in the bottom. Pls consider to add a automated job to remove old entries') ?>"><?= t('Log Anonymus User') ?></label>
            <div class="radio">
                <label>
                    <?= $form->radio('log_anonymus_users', 'yes', $log_anonymus_users) ?>
                    <span><?= t('On') ?></span>
                </label>
            </div>
            <div data-fields="log_anonymus_users" style="padding-left: 30px;">
                <div class="help-block">
                    <div>
                        <a href="/index.php/dashboard/system/optimization/jobs" target="_self">
                            <?= t('Create an automated job, to remove old entries. All with an expired refresh token will be deleted.') ?>
                        </a>
                    </div>
                    <div style="max-height: 500px; overflow-y: auto; overflow-x: hidden; margin-top: 15px;">
                        <div style="background-color: #ccc; padding: 5px;">
                            <div class="row">
                                <div class="col-xs-1">uID</div>
                                <div class="col-xs-3"><?= t('Name') ?></div>
                                <div class="col-xs-1"><?= t('Date Added') ?></div>
                                <div class="col-xs-1"><?= t('IP') ?></div>
                                <div class="col-xs-3"><?= t('Agent') ?></div>
                                <div class="col-xs-1"><?= t('Timezone') ?></div>
                                <div class="col-xs-2"><?= t('Default Language') ?></div>
                            </div>
                        </div>
                        <div style="padding: 5px;">
                            <?php
                            foreach ($anonymusUsers as $anonymusUser) {
                                ?>
                                <div class="row">
                                    <div class="col-xs-1"><?= $anonymusUser->getUserID() ?></div>
                                    <div class="col-xs-3"><?= $anonymusUser->getUserName() ?></div>
                                    <div class="col-xs-1"><?= $dh->formatDateTime($anonymusUser->getUserDateAdded()) ?></div>
                                    <div class="col-xs-1"><?= $anonymusUser->getUserLastIP() ?></div>
                                    <div class="col-xs-3"><?= $anonymusUser->getUserLastAgent() ?></div>
                                    <div class="col-xs-1"><?= $anonymusUser->getUserTimezone() ?></div>
                                    <div class="col-xs-2"><?= $anonymusUser->getUserDefaultLanguage() ?></div>
                                </div>
                            <?php
                            }
                            ?>
                        </div>
                    </div>
                </div>
            </div>

            <div class="radio">
                <label>
                    <?= $form->radio('log_anonymus_users', 'no', !$log_anonymus_users) ?>
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

<script>
    $(function() {
        $('input[name=log_anonymus_users]').change(function() {
            var $selected = $('input[name=log_anonymus_users]:checked');
            if ($selected.val() === 'yes') {
                $('div[data-fields=log_anonymus_users]').show();
            } else {
                $('div[data-fields=log_anonymus_users]').hide();
            }
        });

        $('input[name=log_anonymus_users]:checked').trigger('change');
    });
</script>