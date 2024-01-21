<?php

namespace App\Http\Controllers\Api;

use Exception;
use Rules\Password;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use App\Helpers\ResponseFormatter;
use App\Http\Controllers\Controller;
use App\Http\Resources\UserResource;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Redis;
use Spatie\QueryBuilder\QueryBuilder;
use App\Http\Resources\UserCollection;
use Symfony\Component\HttpFoundation\Response;
use App\Http\Requests\Api\User\StoreUserRequest;
use App\Http\Requests\Api\User\UpdateUserRequest;
use App\Http\Requests\Api\User\DestroyManyRequest;
use Illuminate\Http\Resources\Json\AnonymousResourceCollection;

class UserController extends Controller
{
    /**
     * Handle permission of this resource controller.
     */
    public function __construct()
    {
        $this->authorizeResource(User::class, 'user');
    }

    /**
     * Display a listing of the resource.
     *
     * @return JsonResponse
     */
    public function index(Request $request)
    {
        $q = $request->get('q');
        $perPage = $request->get('per_page', 10);
        $sort = $request->get('sort');

        $users = QueryBuilder::for(User::class)
                            ->with([
                                'roles' => [
                                    'permissions',
                                ]
                            ])
                            ->allowedSorts(['name', 'email','phone', 'post_code', 'city', 'country', 'created_at'])
                            ->where('name', 'like', "%$q%")
                            ->orWhere('email', 'like', "%$q%")
                            ->WithoutAuthUser()
                            ->WithoutSuperAdmin()
                            ->latest()
                            ->paginate($perPage)
                            ->appends(['per_page' => $perPage, 'q' => $q, 'sort' => $sort]);

        return UserCollection::make($users);
    }

    /**
     * Store a newly created resource in storage.
     *
     * @param  StoreUserRequest  $request
     * @return JsonResponse
     */
    public function store(StoreUserRequest $request)
    {
        $user = User::create($request->safe(['name', 'username', 'email'])
            + [
                'password' => bcrypt($request->validated(['password'])),
                'email_verified_at' => now(),
            ]);
        $user->assignRole([$request->validated('role')]);

        return $this->responseWithSuccess('User created successfully', [
            'user' => UserResource::make($user)
        ], Response::HTTP_CREATED);
    }

    /**
     * Display the specified resource.
     *
     * @param  User  $user
     * @return JsonResponse
     */
    public function show(User $user)
    {
        return $this->responseWithSuccess('User details', UserResource::make($user));
    }

    /**
     * Update the specified resource in storage.
     *
     * @param  UpdateUserRequest  $request
     * @param  User  $user
     * @return JsonResponse
     */
    public function update(UpdateUserRequest $request, User $user)
    {
        $user->update($request->safe(['name', 'username', 'email'])
            + ['password' => bcrypt($request->validated(['password']))]);

        $user->syncRoles($request->validated(['role']));

        return $this->responseWithSuccess('User updated successfully', UserResource::make($user));
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param  User  $user
     * @return JsonResponse
     */
    public function destroy(User $user)
    {
        try {
            $user->delete();
            return $this->responseWithSuccess('User deleted successfully', [], Response::HTTP_NO_CONTENT);
        } catch (Exception $e) {
            return $this->responseWithError($e->getMessage(), $e->getCode());
        }
    }

    public function destroyMany(DestroyManyRequest $request)
    {
        $this->authorize('destroyMany', User::class);

        User::destroy($request->validated('users'));

        return $this->responseWithSuccess('Users deleted successful!');
    }

    public function register()
    {
        try {
            $request->validate([
                'name' => 'required|string|max:255',
                'username' => 'required|string|max:255',
                'email' => 'required|string|email|max:255|unique:users',
                'phone' => 'nullable|string|max:255',
                'password' => ['required', 'confirmed', new Password],
            ]);

            $user = User::create([
                'name' => $request->name,
                'username' => $request->username,
                'email' => $request->email,
                'phone' => $request->phone,
                'password' => Hash::make($request->password),
            ]);

            $user = User::where('email', $request->email)->first();

            $tokenResult = $user->createToken('authToken')->plainTextToken;

            return ResponseFormatter::success([
                'access_token' => $tokenResult,
                'token_type' => 'Bearer',
                'user' => $user
            ], 'User Registered');
        } catch (Exception $error) {
            return ResponseFormatter::error([
                'message' => 'Something went wrong',
                'error' => $error
            ], 'Authentication Failed', 500);
        }
    }

    public function login(Request $request)
    {
        try {
            $request->validate([
                'email' => 'email|required',
                'password' => 'required'
            ]);

            $credentials = request(['email', 'password']);

            if (!Auth::attempt($credentials)) {
                return ResponseFormatter::error([
                    'message' => 'Unauthorized'

                ], 'Authentication Failed', 500);
            }
            
            $user = User::where('email', $request->email)->first();

            if (!Hash::check($request->password, $user->password, [])) {
                throw new \Exception('Invalid Credentials');
            }

            $tokenResult = $user->createToken('authToken')->plainTextToken;

            return ResponseFormatter::success([
                'access_token' => $tokenResult,
                'token_type' => 'Bearer',
                'user' => $user
            ], 'Authenticated');
        }catch (Exception $error) {
            return ResponseFormatter::error([
                'message' => 'Something went wrong',
                'error' => $error
            ], 'Authentication Failed', 500);
        } 
    }

    public function fetch(Request $request)
    {
        $user = $request->user();

        return ResponseFormatter::success($user, 'Data profile user successfully');
    }

    public function updateProfile(Request $request)
    {
        $data = $request->all();

        $user = Auth::user();
        $user->update($data);

        return ResponseFormatter::success($user, 'Profile updated successfully');
    }

    public function logout(Request $request)
    {
        $token = $request->user()->currentAccessToken()->delete();

        return ResponseFormatter::success($token, 'Token revoked');
    }

}
