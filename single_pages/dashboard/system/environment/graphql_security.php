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
            <label class="launch-tooltip" for="auth_expire" data-placement="right" title="<?= t('A standard token will expire after how long? Default would be after 300 sec') ?>"><?= t('Token Expire [s]') ?></label>
            <div class="form-group">
                <div class="form-group">
                    <?= $form->text('auth_expire', (int) $auth_expire > 0 ? (int) $auth_expire : 300) ?>
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
                    <span><?= t('Off') ?></span>
                </label>
            </div>
        </div>

        <div class="form-group" style="margin-top: 30px;">
            <label class="launch-tooltip" data-placement="right" title="<?= t('Logs anonymus user in the database, you will see the table here in the bottom. Pls consider to add a automated job to remove old entries') ?>"><?= t('Log Anonymus User') ?></label>
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
                    <div style="margin-top: 15px;">
                        <div class="anonymus-user-table">
                            <div style="min-height: 30px;">
                                <i class="fa fa-spinner fa-spin"></i>
                            </div>
                            <div style="background-color: #ccc; padding: 5px;">
                                <div class="row" style="padding-bottom: 15px;">
                                    <div class="col-xs-1">uID</div>
                                    <div class="col-xs-3"><?= t('Name') ?></div>
                                    <div class="col-xs-1"><?= t('Date Added') ?></div>
                                    <div class="col-xs-1"><?= t('IP') ?></div>
                                    <div class="col-xs-3"><?= t('Agent') ?></div>
                                    <div class="col-xs-1"><?= t('Timezone') ?></div>
                                    <div class="col-xs-2"><?= t('Default Language') ?></div>
                                </div>
                                <div class="row" style="padding-bottom: 15px;">
                                    <div class="col-xs-1"></div>
                                    <div class="col-xs-3"><?= t('Authorize secret') ?></div>
                                    <div class="col-xs-1"><?= t('Authorize secret revoke') ?></div>
                                    <div class="col-xs-1"><?= t('Token not before') ?></div>
                                    <div class="col-xs-3"><?= t('Token expires') ?></div>
                                    <div class="col-xs-1"><?= t('Refresh token expires') ?></div>
                                    <div class="col-xs-2"><?= t('Last request') ?></div>
                                </div>
                                <div class="row">
                                    <div class="col-xs-1"></div>
                                    <div class="col-xs-3"><?= t('Last request IP') ?></div>
                                    <div class="col-xs-1"><?= t('Last request agent') ?></div>
                                    <div class="col-xs-1"><?= t('Last request timezone') ?></div>
                                    <div class="col-xs-3"><?= t('Last request language') ?></div>
                                    <div class="col-xs-1"><?= t('Request count') ?></div>
                                    <div class="col-xs-2"></div>
                                </div>
                            </div>
                            <div class="table-content" style="padding: 5px; max-height: 500px; overflow-y: auto; overflow-x: hidden;">
                            </div>
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

        <div class="form-group" style="margin-top: 30px;">
            <label class="launch-tooltip" data-placement="right" title="<?= t('Logs the last request time, ip, agent, timezone, language and the request count to a concrete5 or anonymus user') ?>"><?= t('Log User Requests') ?></label>
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
    </fieldset>

    <div class="ccm-dashboard-form-actions-wrapper">
        <div class="ccm-dashboard-form-actions">
            <a class="pull-left btn btn-danger" name="delete-all-anonymus-users" href="javascript:void(0);">
                <?= t('Delete all anonymus users') ?>
            </a>
            <button class="pull-right btn btn-primary" type="submit"><?= t('Save') ?></button>
        </div>
    </div>

</form>

<script data-template='add-anonymus-table-row' type="text/template" charset="utf-8">
    <div class="row" style="padding-bottom: 15px;">
        <div class="col-xs-1"><%= row.uID %></div>
        <div class="col-xs-3"><%= row.uName %></div>
        <div class="col-xs-1"><%= row.uDateAdded.date %></div>
        <div class="col-xs-1"><%= row.uLastIP %></div>
        <div class="col-xs-3"><%= row.uLastAgent %></div>
        <div class="col-xs-1"><%= row.uTimezone %></div>
        <div class="col-xs-2"><%= row.uDefaultLanguage %></div>
    </div>
    <div class="row" style="padding-bottom: 15px;">
        <div class="col-xs-1"></div>
        <div class="col-xs-3"><%= row.uGraphqlJwtAuthSecret %></div>
        <div class="col-xs-1"><%= row.uGraphqlJwtAuthSecretRevoked %></div>
        <div class="col-xs-1"><%= row.uGraphqlJwtTokenNotBefore ? new Date(row.uGraphqlJwtTokenNotBefore * 1000).toLocaleString() : '' %></div>
        <div class="col-xs-3"><%= row.uGraphqlJwtTokenExpires ? new Date(row.uGraphqlJwtTokenExpires * 1000).toLocaleString() : '' %></div>
        <div class="col-xs-1"><%= row.uGraphqlJwtRefreshTokenExpires ? new Date(row.uGraphqlJwtRefreshTokenExpires * 1000).toLocaleString() : '' %></div>
        <div class="col-xs-2"><%= row.uGraphqlJwtLastRequest ? new Date(row.uGraphqlJwtLastRequest * 1000).toLocaleString() : '' %></div>
    </div>
    <div class="row">
        <div class="col-xs-1"></div>
        <div class="col-xs-3"><%= row.uGraphqlJwtLastRequestIp %></div>
        <div class="col-xs-1"><%= row.uGraphqlJwtLastRequestAgent %></div>
        <div class="col-xs-1"><%= row.uGraphqlJwtLastRequestTimezone %></div>
        <div class="col-xs-3"><%= row.uGraphqlJwtLastRequestLanguage %></div>
        <div class="col-xs-1"><%= row.uGraphqlJwtRequestCount %></div>
        <div class="col-xs-2"></div>
    </div>
    <div class="row">
        <div class="col-xs-12"><hr></div>
    </div>
</script>

<script>
    $(function() {
        var $deleteAllAnonymusUser = $('a[name="delete-all-anonymus-users"]')
        tokenName = <?= json_encode($token::DEFAULT_TOKEN_NAME) ?>,
            actions = <?= json_encode([
                            'deleteAllAnonymusUser' => [
                                'url' => (string) $view->action('deleteAllAnonymusUser'),
                                'token' => $token->generate('ccm-delete-all-anonymus-user'),
                            ],
                        ]) ?>;

        function ajax(which, data, onSuccess, onError) {
            data[tokenName] = actions[which].token;
            $.ajax({
                data: data,
                dataType: 'json',
                method: 'POST',
                url: actions[which].url
            }).done(function() {
                onSuccess();
            }).fail(function(xhr, status, error) {
                var msg = error;
                if (xhr.responseJSON && xhr.responseJSON.error) {
                    msg = xhr.responseJSON.error.message || xhr.responseJSON.error;
                }
                window.alert(msg);
                onError();
            });
        }

        $deleteAllAnonymusUser.click(function() {
            if (confirm("<?= t('Are you sure, that you want to delete all anonymus users?') ?>")) {
                $(document.body).css({
                    'cursor': 'wait'
                });

                ajax(
                    'deleteAllAnonymusUser', {},
                    function() {
                        $(document.body).css({
                            'cursor': 'default'
                        });
                    },
                    function() {
                        $(document.body).css({
                            'cursor': 'default'
                        });
                    }
                );
            }
        });

        $('input[name=log_anonymus_users]').change(function() {
            var $selected = $('input[name=log_anonymus_users]:checked');
            if ($selected.val() === 'yes') {
                $('div[data-fields=log_anonymus_users]').show();
            } else {
                $('div[data-fields=log_anonymus_users]').hide();
            }
        });

        $('input[name=log_anonymus_users]:checked').trigger('change');

        function updateAnonymusUserTable() {
            var $table = $('.anonymus-user-table'),
                _addAnonymusTableRowTemplate = _.template($('script[data-template=add-anonymus-table-row]').html());

            $table.find('i').show();

            $.ajax({
                    cache: false,
                    data: {
                        <?= json_encode($token::DEFAULT_TOKEN_NAME) ?>: <?= json_encode($token->generate('ccm-update-anonymus-user-table')) ?>,
                    },
                    dataType: 'json',
                    method: 'POST',
                    url: <?= json_encode((string) $view->action('getAnonymusUserTable')) ?>
                })
                .done(function(rows) {
                    $table.find('.table-content').html('');

                    for (var row of rows) {
                        $table.find('.table-content').append(
                            _addAnonymusTableRowTemplate({
                                'row': row,
                            })
                        );
                    }
                })
                .fail(function() {
                    $table.find('.table-content').html('?');
                })
                .always(function() {
                    $table.find('i').hide();
                    setTimeout(
                        function() {
                            updateAnonymusUserTable();
                        },
                        1000
                    );
                });
        }
        updateAnonymusUserTable();
    });
</script>