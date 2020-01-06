<?php

namespace App\Http\Controllers\Auth;

use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Auth\Events\Verified;
use Illuminate\Foundation\Auth\VerifiesEmails;
use App\User;

class VerificationController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Email Verification Controller
    |--------------------------------------------------------------------------
    |
    | This controller is responsible for handling email verification for any
    | user that recently registered with the application. Emails may also
    | be re-sent if the user didn't receive the original email message.
    |
    */

    use VerifiesEmails;

    /**
     * Where to redirect users after verification.
     *
     * @var string
     */
    // protected $redirectTo = '/home';

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('api.auth')->except('verify');
        $this->middleware('signed')->only('verify');
        $this->middleware('throttle:6,1')->only('verify', 'resend');
    }

    /**
     * Mark the authenticated user's email address as verified.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     * @throws \Illuminate\Auth\Access\AuthorizationException
     */
    public function verify(Request $request)
    {
        if ($request->user()) { // if user is logged in

            if ($request->route('id') != $request->user()->getKey()) {
                throw new AuthorizationException;
            }
    
            if ($request->user()->hasVerifiedEmail()) {
                return $this->response->array(['message' => 'User already have verified email!'], 401);
            }
    
            if ($request->user()->markEmailAsVerified()) {
                event(new Verified($request->user()));
                return $this->response->array(['message' => 'Email verified!', 'verified' => true]);
            }
        } else {
            
            $user = User::find($request->route('id'));
    
            if ($user->hasVerifiedEmail()) {
                return $this->response->array(['message' => 'User already have verified email!'], 401);
            }
    
            if ($user->markEmailAsVerified()) {
                event(new Verified($user));
                return $this->response->array(['message' => 'Email verified!', 'verified' => true]);
            }
        }
    }

    /**
     * Resend the email verification notification.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function resend(Request $request)
    {
        if ($request->user()->hasVerifiedEmail()) {
            return $this->response->array(['message' => 'User already have verified email!']);
        }

        $request->user()->sendEmailVerificationNotification();

        return $this->response->array(['message' => 'The verification email has been resent.']);
    }
}
