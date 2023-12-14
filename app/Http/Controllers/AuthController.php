<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Laravel\Socialite\Facades\Socialite;
use Illuminate\Support\Facades\Auth;
use App\Models\User;

class AuthController extends Controller
{

    public function __construct()
    {
        $this->middleware('guest')->except('logout');
    }

    public function login()
    {
        return view('auth.login');
    }

    public function redirectToGoogle()
    {
        return Socialite::driver('google')->redirect();
    }

    public function handleGoogleCallback()
    {
        $user = Socialite::driver('google')->user();
        $localUser = User::where('email', $user->email)->first();

        if (!$localUser) {
            $localUser = User::create([
                'name' => $user->name,
                'email' => $user->email,
                'google_id' => $user->id,
                'password' => Hash::make(Str::random(20)),
            ]);
        }

        Auth::login($localUser);
        return redirect('/home');
    }

    public function redirectToMicrosoft()
    {
        $query = http_build_query([
            'client_id' => config('services.microsoft.client_id'),
            'redirect_uri' => config('services.microsoft.redirect'),
            'response_type' => 'code',
            'scope' => 'openid profile email', // Add more scopes if needed
        ]);

        return redirect('https://login.microsoftonline.com/common/oauth2/v2.0/authorize?' . $query);
    }

    public function handleMicrosoftCallback()
    {
        $response = Http::asForm()->post('https://login.microsoftonline.com/common/oauth2/v2.0/token', [
            'client_id' => config('services.microsoft.client_id'),
            'client_secret' => config('services.microsoft.client_secret'),
            'code' => request('code'),
            'grant_type' => 'authorization_code',
            'redirect_uri' => config('services.microsoft.redirect'),
        ]);

        $user = Http::withToken($response['access_token'])->get('https://graph.microsoft.com/v1.0/me')->json();

        // Your logic to authenticate or register the user
        // Example: Check if user already exists, create a new user, etc.

        Auth::login($user);

        return redirect('/home'); // Redirect to the home page after login
    }
}