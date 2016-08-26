<?php

namespace Essentials\OAuth;

use Essentials\OAuth\Services\OAuthGuard;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;

class AuthServiceProvider extends ServiceProvider
{
    /**
     * Perform post-registration booting of services.
     *
     * @return void
     */
    public function boot()
    {
        Auth::extend('oauth', function($app, $name, array $config) {
            return new OAuthGuard(Auth::createUserProvider($config['provider']), $this->app['request']);
        });
    }

    /**
     * Register bindings in the container.
     *
     * @return void
     */
    public function register()
    {
        //
    }
}