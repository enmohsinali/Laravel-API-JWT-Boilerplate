<?php

use Illuminate\Http\Request;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

/**
 * @var \Dingo\Api\Routing\Router
 */
$api = app('Dingo\Api\Routing\Router');
// Verification and Reset
Auth::routes(['verify' => true]);
    

$api->version('v1', ['middleware' => ['api']], function ($api) {
    $api->get(
        'index',
        'App\Http\Controllers\HomeController@index'
    );
    // Register and Login Routes
    $api->post('login', 'App\Http\Controllers\Auth\LoginController@login');
    $api->post('register', 'App\Http\Controllers\Auth\RegisterController@register');

});

$api->version('v1',['middleware'=>['api','auth:api']],function ($api){
    
    $api->post('/logout', 'App\Http\Controllers\Auth\LoginController@logout');

});
/*
Route::middleware('auth:api')->get('/user', function (Request $request) {
    return $request->user();
});
*/