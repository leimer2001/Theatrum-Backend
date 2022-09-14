<?php

namespace App\Http\Controllers\Api;


use App\Models\User;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function createUser(Request $request)
    {

        try{
            $validateUser = Validator::make($request->all(),
            [
                'firstname' => ['required', 'string', 'max:255'],
                'lastname' => ['required', 'string', 'max:255'],
                'username' => ['required', 'string', 'max:255'],
                'email' => ['required', 'string', 'email', 'max:255', 'unique:users'],
                'password' => ['required', 'string', 'min:8']
            ]);
        
            if($validateUser->fails()){
                return response()->json([
                    'status' => false,
                    'message' => 'validation Error',
                    'errors' => $validateUser->errors()
                ],401);
            }

            $user = User::create([
                'firstname' => $request->firstname,
                'lastname' => $request->lastname,
                'username' => $request->username,
                'email' => $request->email,
                'password' => Hash::make($request->password),
            ]);

            return response()->json([
                'status' => true,
                'message' => 'User Created Succesfully',
                'token' => $user->createToken("API TOKEN")->plainTextToken
            ],200);
             


        }catch(\Throwable $th){
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ],500);
        }

        
    }

    
    public function loginUser(Request $request)
    {
        try{
            $validateUser = Validator::make($request->all(),
            [ 
                'email' => 'required|email',
                'password' => 'required'
            ]);

            
            if($validateUser->fails()){
                return response()->json([
                    'status' => false,
                    'message' => 'validation Error',
                    'errors' => $validateUser->errors()
                ],401);
            }

            $login = $request->only(['email','password']);

            if(!Auth::attempt($login)){
                return response()->json([
                    'status' => false,
                    'message' => 'Login failed. Check your account credential.'
                ],401);

            }

            $user = User::where('email', $request->email)->first();
                return response()->json([
                    'status' => true,
                    'message' => 'User Logged In Succesfully',
                    'token' => $user->createToken("API TOKEN")->plainTextToken
                ],200);

        }catch(\Throwable $th){
            return response()->json([
                'status' => false,
                'message' => $th->getMessage(),
            ],500);
        }
    }
}
