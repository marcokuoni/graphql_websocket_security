<?php

namespace Helpers;

use Concrete\Core\Config\Repository\Repository;
use Concrete\Core\Http\Middleware\DelegateInterface;
use Concrete\Core\Http\Middleware\MiddlewareInterface;
use Symfony\Component\HttpFoundation\Request;
use Concrete\Core\Support\Facade\Application as App;
use Concrete\Core\User\User;

/**
 * Custom middleware that adds information to the response
 */
class Middleware implements MiddlewareInterface
{
    /** @var \Concrete\Core\Config\Repository\Repository */
    protected $config;
    public function __construct(Repository $config)
    {
        $this->config = $config;
    }
    /**
     * Process the request and return a response
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @param DelegateInterface $frame
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function process(Request $request, DelegateInterface $frame)
    {
        // Get the response object from the next middleware
        $response = $frame->next($request);

        $authorize = App::make(\Helpers\Authroize::class);

        /**
         * Note: The Access-Control-Expose-Headers aren't directly filterable
         * for REST API responses, so this overrides them altogether.
         *
         * This isn't ideal, as any other plugin could override as well.
         *
         * Might need a patch to core to allow for individual filtering.
         */
        $response->headers->add([
            'Access-Control-Expose-Headers' => 'X-WP-Total, X-WP-TotalPages, X-JWT-Refresh',
        ]);

        $refreshToken = null;

        $validateAuthHeader = $authorize->validateToken(str_ireplace('Bearer ', '', $authorize->getAuthHeader()), false);

        if (!empty($validateAuthHeader->data->user->uID)) {
            $user = $authorize->authenticated($validateAuthHeader);
            $refreshToken = $authorize->getRefreshToken($user, false);
        }

        if ($refreshToken) {
            $response->headers->add([
                'X-JWT-Refresh' => $refreshToken,
            ]);
        }

        return $response;
    }
}
