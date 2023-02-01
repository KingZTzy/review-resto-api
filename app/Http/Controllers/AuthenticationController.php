<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

class AuthenticationController extends Controller
{
    public function login(Request $request) 
    {
        $request->validate([
            'email' => 'required|String|email',
            'password' => 'required',
            'device_name' => 'required|String'
        ]);

        $user = User::whereEmail($request->email)->first();
        if(!$user || !Hash::check($request->password, $user->password)) {
            throw ValidationException::withMessages([
                'email' => 'Alamat Email Atau Password Salah',
            ]);
        }

        return [
            'access_token' => $user->createToken($request->device_name)->plainTextToken,
            'user' => $user,
        ];
    }

    public function logout(Request $request)
    {
        return $request->user()->currentAccessToken()->delete();
    }

    public function register(Request $request) 
    {
        $request->validate([
            'name' => 'required|String|max:255',
            'email' => 'required|String|email|unique:users,email',
            'password' => 'required|confirmed',
        ]);

        return User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password),
        ]);
    }

    public function profile(Request $request)
    {
        return $request->user();
    }
}
