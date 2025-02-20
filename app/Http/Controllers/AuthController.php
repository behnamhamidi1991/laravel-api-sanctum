<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    /**
     * Register a user
     * 
     * @param Request $request
     * @return HttpResponse $200
     */
    public function register(Request $request)
    {
        // $validatedData = $request->validate([
        //     'name' => 'required|string|max:255',
        //     'email' => 'required|string|email|max:255|unique:users',
        //     'password' => 'required|string|min:6|confirmed'
        // ]);

        $validatedData = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6|confirmed'
        ]);

        if ($validatedData->fails()) {
            return response()->json($validatedData->errors(), 422);
        }

        try {
            $user = User::create([
                'name' => $validatedData['name'],
                'email' => $validatedData['email'],
                'password' => Hash::make($request->password)
            ]);
    
            $token = $user->createToken('auth_token')->plainTextToken;
    
            // return 
            return response()->json([
                'access_token' => $token,
                'user' => $user
            ], 200);
        } catch (\Exception $e) {
            return response()->json(['error' => $e->getMessage()]);
        }
    }

    /**
     * Login a user
     * 
     * @param Request $request
     * @return HttpResponse $200
     */
    public function login (Request $request)
    {
        $validatedData = Validator::make($request->all(), [
            'email' => 'required|string|email',
            'password' => 'required|string|min:6'
        ]);

        if($validatedData->fails()) {
            return response()->json($validatedData->errors(), 422);
        }

        $credentials = ['email' => $request->email, 'password' => $request->password];

        try {
            if (!Auth()->attempt($credentials)) {
                return response()->json(['error' => 'Invalid Credentials'], 403);
            }

            $user = User::where('email', $request->email)->firstOrFail();

            $token = $user->createToken('auth_token')->plainTextToken;

            // Return value
            return response()->json([
                'access_token' => $token,
                'user' => $user,
            ], 200);
        } catch (\Exception $e) {
            return response()->json(['error' => $e->getMEssage()], 403);
        }
    }

    /**
     * Logout
     * 
     * @param Request $request
     * @return HttpResponse
     */
    public function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();

        // Return Value
        return response()->json([
            'user' => 'User has been logged out successfully!',
        ], 200);
    }
}
