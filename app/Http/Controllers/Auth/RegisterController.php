<?php

namespace App\Http\Controllers\Auth;

use App\User;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Foundation\Auth\RegistersUsers;
use Illuminate\Auth\Events\Registered;
use Spatie\Permission\Models\Role;

class RegisterController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Register Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles the registration of new users as well as their
    | validation and creation. By default this controller uses a trait to
    | provide this functionality without requiring any additional code.
    |
    */

    use RegistersUsers;

    /**
     * Where to redirect users after registration.
     *
     * @var string
     */
    protected $redirectTo = '/home';

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest');
    }

    /**
     * Handle a registration request for the application.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function register(Request $request)
    {
        $validator = $this->validator($request->all());
        if ($validator->fails()) {
            throw new \Dingo\Api\Exception\StoreResourceFailedException('Validation error occur.', $validator->errors());
        }

            event(new Registered($user = $this->create($request->all())));
            
            if ($user) {
                return $this->response->array([
                    "message" => "Registered successfully please verify your email.",
                    "status_code" => 200
                ]);
            } else {
                return $this->response->error("User not found...", 404);
            }
    }

    /**
     * Get a validator for an incoming registration request.
     *
     * @param  array  $data
     * @return \Illuminate\Contracts\Validation\Validator
     */
    protected function validator(array $data)
    {
        return Validator::make($data, [
            'name' => ['required', 'string', 'min:3'],
            // 'username' => ['required', 'string', 'min:6', 'unique:users'],
            'email' => ['required', 'string', 'email', 'max:255', 'unique:users'],
            'password' => ['required', 'string', 'min:6'],
        ]);
    }

    /**
     * Create a new user instance after a valid registration.
     *
     * @param  array  $data
     * @return \App\User
     */
    protected function create(array $data)
    {
        return User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'username'=>$data['email'],
            'password' => Hash::make($data['password']),
            'enabled' => 1,
            'country' => (isset($data['country'])) ? $data['country'] : '',
            'timezone' => (isset($data['timezone'])) ? $data['timezone'] : '',
        ]);
    }

    /**
     * Generate username for firstname, lastname and last 3 digits of phone number.
     *
     * @param  string  $fullname, @param string $phone, @param int $count for last 3 digits of phone
     * @return string $username
     */
    protected function generate_username($fullname)
    {
        $pattern = " ";
        $firstPart = strstr(strtolower($fullname), $pattern, true);
        $secondPart = substr(strstr(strtolower($fullname), $pattern, false), 0, 3);
        $nrRand = rand(0, 1000);

        $username = trim($firstPart) . trim($secondPart) . trim($nrRand);
        if ($this->username_exist($username)) {
            return $this->generate_username($fullname);
        } else {
            return $username;
        }

        return $username;
    }

    /**
     * Check username exist or not in database.
     *
     * @param  string  $username
     * @return boolean \App\User
     */
    protected function username_exist($username)
    {
        return User::where('username', $username)->exists();
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
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60,
            'user' => auth()->user()
        ]);
    }
}
