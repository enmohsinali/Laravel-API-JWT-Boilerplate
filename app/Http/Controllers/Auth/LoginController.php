<?php

namespace App\Http\Controllers\Auth;

use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Illuminate\Support\Facades\Validator;
use App\User;
use Socialite;

class LoginController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Login Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles authenticating users for the application and
    | redirecting them to your home screen. The controller uses a trait
    | to conveniently provide its functionality to your applications.
    |
    */

    use AuthenticatesUsers;

    /**
     * Where to redirect users after login.
     *
     * @var string
     */
    protected $redirectTo = '/home';
    protected $username;

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest')->except('logout');
        $this->username = $this->field();
    }

    /**
     * Check credentials and Login to user.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|string',
            'password'=> 'required'
        ]);

        if ($validator->fails()) {
            throw new \Dingo\Api\Exception\StoreResourceFailedException('Validation error occur.', $validator->errors());
        }

        try {
            if (! $token = \JWTAuth::attempt($this->credentials($request))) {
                return $this->response->error('Email or Password is not correct!', 401);
            }
        } catch (JWTException $e) {
            return $this->response->error('Could not create token', 500);
        }
        
        // Check if user has verified email address or not.
        // $isVerified = User::where('email', $request->email)->orwhere('username', $request->email)->first()->hasVerifiedEmail();
        // if (!$isVerified) {
        //     return $this->response->error('Your email address is not verified.', 403);
        // }
        
        if ($this->attemptLogin($request)) {
            return $this->respondWithToken($token);
        }

        return $this->response->array(['error' => trans('auth.failed')]);
    }

    /**
     * Attempt to log the user into the application.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return bool
     */
    protected function attemptLogin(Request $request)
    {
        return $this->guard()->attempt(
            $this->credentials($request), $request->filled('remember')
        );
    }

    /**
     * Get the needed authorization credentials from the request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return array
     */
    protected function credentials(Request $request)
    {
        return $request->only($this->username(), 'password');
    }

    /**
     * Get the guard to be used during authentication.
     *
     * @return \Illuminate\Contracts\Auth\StatefulGuard
     */
    protected function guard()
    {
        return \Auth::guard();
    }

    /**
     * Determine if the request field is email or username.
     *
     * @return string
     */
    public function field()
    {
        $email = request()->input('email');

        $fieldType = filter_var($email, FILTER_VALIDATE_EMAIL) ? 'email' : 'username';
        request()->merge([$fieldType => $email]);
        
        return $fieldType;
    }

    /**
     * Get the login username or email to be used by the controller.
     *
     * @return string
     */
    public function username()
    {
        return $this->username;
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return Dingo\Api\ArrayResponse
     */
    protected function respondWithToken($token)
    {
        return $this->response->array([
            'token' => $token,
            'expires_in' => auth()->factory()->getTTL() * 60,
        ]);
    }

    /**
     * Logout
     *
     * Invalidate the token. User have to relogin to get a new token.
     *
     * @param Request $request 'header'
    */
    public function logout(Request $request) 
    {
        // Get JWT Token from the request header key "Authorization"
        $token = $request->header('Authorization');
        
        // Logout the authentic user using jwt
        auth()->logout();

        // Invalidate the token
        try {

            \JWTAuth::invalidate($token);
            return $this->response->array([
                'message'=> "User successfully logged out.",
                'status_code' => 200, 
            ]);

        } catch (\JWTException $e) {
            
            // something went wrong whilst attempting to encode the token
            return $this->response->error('Failed to logout, please try again.', 500);
        }
    }

    /**
     * Obtain the user information from Social.
     *
     * @param string $social
     * @return \Illuminate\Http\Response
     */
    public function handleProviderCallback(Request $request, $social)
    {
        if ($request->has('email')) {
            $user = User::where('email', $request->email)->first();
            if($user) {
                if (!$userToken = \JWTAuth::fromUser($user)) {
                    return $this->response->error('Email or Password is not correct!', 401);
                }
                \Auth::login($user);
                return $this->respondWithToken($userToken);
            } else {
                if ($request->has('popup')) {
                    $queryParam = array(
                        'firstname' => $request->firstName,
                        'lastname' => $request->lastName,
                        'email' => $request->email,
                        'id' => $request->id,
                        'provider' => $request->provider,
                        'photo' => str_replace('normal', 'large', $request->photoUrl)
                    );
                } else {
                    $queryParam = '?firstname='.$request->firstName.'&&lastname='.$request->lastName.'&&email='.$request->email.'&&id='.$request->id.'&&provider='.$request->provider.'&&photo='.str_replace('normal', 'large', $request->photoUrl);
                }
                
                return $this->response->array(['register' => true, 'queryParam' => $queryParam]);
            }
        }
    }
}
