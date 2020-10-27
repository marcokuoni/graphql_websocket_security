<?php

namespace Helpers;


use Concrete\Core\Controller\AbstractController;
use Concrete\Core\Http\Client\Client as HttpClient;
use Concrete\Core\Logging\Channels;
use Concrete\Core\Logging\LoggerAwareInterface;
use Concrete\Core\Logging\LoggerAwareTrait;
use Concrete\Core\Permission\IPService;
use Exception;
use Psr\Log\LogLevel;

class GoogleRecaptchaCheck extends AbstractController implements LoggerAwareInterface
{
    use LoggerAwareTrait;

    /**
     * Response error code: The secret parameter is missing.
     *
     * @var string
     *
     * @see https://developers.google.com/recaptcha/docs/verify#error-code-reference
     */
    const ERRCODE_SECRET_MISSING = 'missing-input-secret';

    /**
     * Response error code: The secret parameter is invalid or malformed.
     *
     * @var string
     *
     * @see https://developers.google.com/recaptcha/docs/verify#error-code-reference
     */
    const ERRCODE_SECRET_INVALID = 'invalid-input-secret';

    /**
     * Response error code: The response parameter is missing.
     *
     * @var string
     *
     * @see https://developers.google.com/recaptcha/docs/verify#error-code-reference
     */
    const ERRCODE_RESPONSE_MISSING = 'missing-input-response';

    /**
     * Response error code: The response parameter is invalid or malformed.
     *
     * @var string
     *
     * @see https://developers.google.com/recaptcha/docs/verify#error-code-reference
     */
    const ERRCODE_RESPONSE_INVALID = 'invalid-input-response';

    /**
     * Response error code: The request is invalid or malformed.
     *
     * @var string
     *
     * @see https://developers.google.com/recaptcha/docs/verify#error-code-reference
     */
    const ERRCODE_REQUEST_INVALID = 'bad-request';

    /**
     * Response error code: The response is no longer valid: either is too old or has been used previously.
     *
     * @var string
     *
     * @see https://developers.google.com/recaptcha/docs/verify#error-code-reference
     */
    const ERRCODE_RESPONSE_TIMEOUT = 'timeout-or-duplicate';

    /**
     * {@inheritdoc}
     *
     * @see \Concrete\Core\Logging\LoggerAwareInterface::getLoggerChannel()
     */
    public function getLoggerChannel()
    {
        return Channels::CHANNEL_SPAM;
    }

    public function check($token, $action)
    {
        $config = $this->app->make('config');
        $queryString = http_build_query(
            [
                'secret' => $config->get('captcha.recaptcha_v3.secret_key'),
                'remoteip' => $config->get('captcha.recaptcha_v3.send_ip') ? (string) $this->app->make(IPService::class)->getRequestIPAddress() : '',
                'response' => $token,
                // 'response' => $this->request->request->get('g-recaptcha-response'),
            ]
        );
        $verifyUrl = $config->get('captcha.recaptcha_v3.url.verify');
        $verifyUrl .= (strpos($verifyUrl, '?') === false ? '?' : '&') . $queryString;

        $httpClient = $this->app->make(\Concrete\Core\Http\Client\Client::class);
        $httpClient->setUri($verifyUrl);

        try {
            $response = $httpClient->send();
        } catch (Exception $x) {
            $this->logger->alert(t('Error loading reCAPTCHA: %s', $x->getMessage()));

            return false;
        }
        /** @var \Zend\Http\Response $response */
        if (!$response->isOk()) {
            $this->logger->alert(t('Error loading reCAPTCHA: %s', sprintf('%s (%s)', $response->getStatusCode(), $response->getReasonPhrase())));

            return false;
        }
        $data = @json_decode($response->getBody(), true);
        if (!is_array($data)) {
            $this->logger->alert(t('Error loading reCAPTCHA: %s', t('invalid response')));

            return false;
        }

        if (!empty($data['error-codes'])) {
            switch (true) {
                case in_array(static::ERRCODE_SECRET_MISSING, $data['error-codes']):
                case in_array(static::ERRCODE_SECRET_INVALID, $data['error-codes']):
                    $logLevel = LogLevel::ALERT;
                    break;
                default:
                    // Don't ring the bells in case the client is sending mangled data: it's likely to happen in case of spammers
                    $logLevel = LogLevel::NOTICE;
                    break;
            }
            $this->logger->log($logLevel, t('Errors in reCAPTCHA validation: %s', implode(', ', $data['error-codes'])));
        }

        $score = array_get($data, 'score');
        if (!is_numeric($score)) {
            // This should happen only when 'error-codes' is not empty, so we already logged the error(s).
            return false;
        }
        $score = (float) $score;
        $minimumScore = $config->get('captcha.recaptcha_v3.score');
        if (array_get($data, 'action') === $action && array_get($data, 'success') === true && $score >= $minimumScore) {
            return true;
        }

        if ($config->get('captcha.recaptcha_v3.log_score') && $score < $minimumScore) {
            $this->logger->notice(t('reCAPTCHA V3 blocked as score returned (%1$s) is below the threshold (%2$s)', $score, $minimumScore));
        }

        return false;
    }
}
