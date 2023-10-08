A date as a string is less reliable than an object instance, e.g. a Carbon-instance. It's recommended to pass Carbon objects between classes instead of date strings. Rendering should be done in the display layer (templates):
A date as a string is less reliable than an object instance, e.g. a Carbon-instance. It's recommended to pass Carbon objects between classes instead of date strings. Rendering should be done in the display layer (templates):
## Contents

[Authentication](#authentication)

[Email verification](#email-verification)

[Reset Password](#reset-password)

["Store service" function](#store-service)

["Service resource" class](#service-resource)

["Buy service" function](#buy-service)

[Subscription](#subscription)


### **authentication**

routes\api.php:

```php
Route::post('register',  [AuthController::class, 'register']);
Route::post('login'   ,  [AuthController::class, 'login']);
```

app\Http\Controllers\AuthController.php:

The constructor, this function is part of a controller class and is responsible for setting up themiddleware for authentication using Laravel Sanctum.
This middleware ensures that the user is authenticated using the Sanctum authentication guardbefore accessing the methods.
The $this->middleware('auth:sanctum')->only(['logout', 'user']); line specifies that the'auth:sanctum' middleware should be applied only to the 'logout' and 'user' methods.

```php
    public function __construct()
    {
        $this->middleware('auth:api')->only(['logout']);
    }
```

```php
    public function register (Request $request) 
    {
        $request->validate([
            'name'       => ['required', 'string'],
            'email'      => ['required', 'string', 'email', 'unique:users'],  
            'password'   => ['required', 'string', 'min:6', 'confirmed'],
        ]);

        $user = User::create([
            'name'      => $request->name,
            'email'     => $request->email,
            'password'  => Hash::make($request->password),
            'role'      => 'user',
            'balance'   => 0,
        ]);

        $token = $user->createToken('Proxy App')->accessToken;
        
        return response()->json([
            'user' => new UserResource($user),
            'token' => $token,
        ], 200);
    }
```

```php
    public function login (Request $request) 
    {
       $request->validate([
            'email'      => ['required', 'string', 'email'],  
            'password'   => ['required', 'string'],
        ]);

        $user = User::where('email', $request->email)->first();

        if ($user) {
            if (Hash::check($request->password, $user->password)) {
                $token = $user->createToken('Mega Panel App')->accessToken;

                return response()->json([
                    'user' => new UserResource($user),
                    'token' => $token,
                ], 200);   
            }
        }
        
        return response()->json([
            'message' => 'email or password is incorrect.',
            'errors' => [
                'email' => ['email or password is incorrect.']
            ]
        ], 422);
    }
```

[🔝 Back to contents](#contents)

### **email-verification**

app\Http\Controllers\EmailVerificationController.php:

```php
public function send_verification_email(Request $request)
{
    $request->validate([
        'email'  => ['required', 'email', 'exists:users,email']
    ]);

    EmailVerificationCode::where('email', $request->email)->delete();
    $email_verification_code = EmailVerificationCode::create([
        'email'  => $request->email,
        'code'   => mt_rand(1000, 9999),
    ]);
    
    Mail::to($request->email)->send(new VerificationEmail($email_verification_code->code));
}
```

```php
    public function verify_email(Request $request)
    {
        $request->validate([
            'code'   => ['required', 'string', 'exists:email_verification_codes'],
        ]);

        $user = Auth::user();
        $email = $user->email;
        $email_verification_code = EmailVerificationCode::where('email', $email)->where('code', $request->code)->first();

        if ($email_verification_code->created_at > now()->addHour()) {
            $email_verification_code->delete();
            return response()->json([
                'message' => 'The verification code is expired.',
                'errors' => [
                    'code' => ['The verification code is expired.']
                ]
            ], 422);
        }

        $user = User::firstWhere('email', $email);
        $user->email_verified_at = Carbon::now();
``        $user->save();
        
        $email_verification_code->delete();
    }
```

[🔝 Back to contents](#contents)

### **reset-password**

app\Http\Controllers\PasswordResetController.php:

```php
    public function send_password_reset_email(Request $request)
    {
        $request->validate([
            'email'  => ['required', 'email', 'exists:users,email']
        ]);

        PasswordResetCode::where('email', $request->email)->delete();
        $password_reset_code = PasswordResetCode::create([
            'email'  => $request->email,
            'code'   => mt_rand(1000, 9999),
        ]);
        
        Mail::to($request->email)->send(new PasswordResetEmail($password_reset_code->code));
    }
```

```php
    public function password_reset(Request $request)
    {
        $request->validate([
            'email'      => ['required', 'email', 'exists:users,email'],
            'code'       => ['required', 'string', 'exists:password_reset_codes'],
            'password'   => ['required', 'string', 'min:6', 'confirmed'],
        ]);

        $password_reset_code = PasswordResetCode::where('email', $request->email)->where('code', $request->code)->first();

        if ($password_reset_code->created_at > now()->addHour()) {
            $password_reset_code->delete();
            return response()->json([
                'message' => 'The reset password code is expired.',
                'errors' => [
                    'code' => ['The reset password code is expired.']
                ]
            ], 422);
        }

        $user = User::firstWhere('email', $request->email);
        $user->password = Hash::make($request->password);
        $user->save();
        
        $password_reset_code->delete();
    }
```

```php
    public function check(Request $request)
    {
        $request->validate([
            'email'      => ['required', 'email', 'exists:users,email'],
            'code'       => ['required', 'string', 'exists:password_reset_codes'],
        ]);

        $password_check = PasswordResetCode::where('email', $request->email)->where('code', $request->code)->first();

        if (!$password_check)
            return response()->json([
                'message' => 'The selected code is wrong.',
                'errors' => [
                    'code' => ['the selected code is wrong.']
                ]
            ], 422);

        return response()->json([
            'message' => 'The selected code is correct.',
            'errors' => [
                'code' => ['the selected code is correct.']
            ]
        ], 200);
    }
```

[🔝 Back to contents](#contents)

### **store-service**

app\Http\Controllers\ServiceController.php:

```php
    public function store(Request $request)
    {
        $request->validate([
            'code'                => ['required', 'string'],
            'name'                => ['required', 'array', translation_rule()],
            'duration'            => ['required', 'in:one_time,daily,weekly,monthly,quarterly,yearly'],
            'description'         => ['required', 'array', translation_rule()],
            'features'            => ['required', 'array', 'min:1'],
            'features.*'          => ['required_array_keys:included,title'],
            'features.*.included' => ['in:0,1'],
            'features.*.title'    => ['array', translation_rule()],
            'price'               => ['required', 'integer', 'min:0'],
            'available'           => ['required', 'boolean'],
            'operations'          => ['required', 'array', 'min:1'],
            'operations.*'        => ['string'],
        ]);

        $features_en = [];
        $features_ar = [];
        foreach($request->features as $feature){
            if($feature['title']['en'])
                $features_en []= ['included' => $feature['included'], 'title' => $feature['title']['en']];
            
            if($feature['title']['ar'])
                $features_ar []= ['included' => $feature['included'], 'title' => $feature['title']['ar']];
        }
    
        $features_en = json_encode($features_en);
        $features_ar = json_encode($features_ar);
        $operations = json_encode($request->operations);

        $service = Service::create([
            'code'         => $request->code,
            'name'         => $request->name,
            'duration'     => $request->duration,
            'description'  => $request->description,
            'features'     => ["en"=> $features_en, "ar"=>$features_ar],
            'price'        => $request->price,
            'available'    => $request->available,
            'operations'   => $operations,
        ]);
        return response()->json(new ServiceResource($service), 201);
    }
```

[🔝 Back to contents](#contents)

### **service-resource**

app\Http\Resources\ServiceResource.php:

```php
class ServiceResource extends JsonResource
{
    public function toArray($request)
    {
        $translations = $this->translations;
        $translations_features = [];
        $translations_features ['en'] = json_decode($translations['features']['en']);
        $translations_features ['ar'] = json_decode($translations['features']['en']);
        $translations['features'] = $translations_features;
        
        return [
            'id'                => $this->id,
            'code'              => $this->code,
            'name'              => $this->name,
            'duration'          => $this->duration,
            'description'       => $this->description,
            'features'          => json_decode($this->features),
            'price'             => $this->price,
            'available'         => $this->available,
            'operations'        => json_decode($this->operations),
            'translations'      => $translations,
            'parameters'        => ServiceParameterResource::collection($this->resource->parameters),
        ];
    }
}
```

[🔝 Back to contents](#contents)

### **buy-service**

```php
    public function buy_service(Request $request, Service $service)
    {
        $request->validate([
            'service_provider_id'  => ['required', 'exists:providers,id'],
            'auto_renew'           => ['boolean'],
        ]);

        $user = to_user(Auth::user());

        if($user->balance < $service->price)
            throw new BadRequestException('You do not have enough balance');
           
        $service_provider = Provider::where('id', $request->service_provider_id)->first();
        
        if($service_provider->enabled == 0)
            throw new BadRequestException('Service provider dose not enable');

        $params_name = [];
        $rules = [];
        
        $parameters = $service->parameters()->whereJsonContains('operations','buy')->get();

        foreach($parameters as $parameter)
        {
            if($parameter->for_user){
                $params_name [] = $parameter->name;
                $parameter->validation_rules = json_decode($parameter->validation_rules);
                $rules[$parameter->name] = $parameter->validation_rules;
            }
        }
        
        $request->validate($rules);
        $params = $request->only($params_name);
        $providerClass = $service_provider->name;
        $provider = new $providerClass();
        $response = $provider->buy($params);

        if(is_array($response) && count($response) > 0)
        {
            $subscription = Subscription::create([
                'user_id'            => $user->id,
                'service_id'         => $service->id,
                'provider_id'        => $service_provider->id,
                'start_date'         => $response['created_at'],
                'expire_date'        => $response['expire_at'],
                'status'             => 'active',
                'price'              => $service->price,
                'provider_service_id'=> $response['id'],
                'data'               => json_encode($response),
                'auto_renew'         => $request->auto_renew?? 0,
            ]);

            $user->balance -= $service->price;
            $user->save();

            return response()->json(new SubscriptionResource($subscription), 201);
        }
        else
            throw new BadRequestException('Service Not Available');
    }
```

[🔝 Back to contents](#contents)

### **subscription**

app\Http\Controllers\SubscriptionController.php:

```php
public function __construct()
{
    $this->middleware('auth:api');
    $this->middleware('role:admin')->only('destroy');
    $this->middleware('verified_email');
}
```

```php
    public function update(Request $request, Subscription $subscription)
    {
        $user = Auth::user();
        if($user->role == 'user'){
            if($subscription->user_id != $user->id)
                throw new BadRequestException('You do not have permissions to access this subscription');
        }

        $request->validate([
            'status'        => ['in:active,expired,canceled'],
            'auto_renew'    => ['boolean'],
        ]);

        $service = Service::where('id', $subscription->service_id)->first();

        $params_name = [];
        $rules = [];
        
        $parameters = $service->parameters()->whereJsonContains('operations','edit')->get();

        foreach($parameters as $parameter)
        {
            if(($user->role == "user" && $parameter->for_user) || (($user->role == "admin" || $user->role == 'employee') && $parameter->for_admin)){
                $params_name [] = $parameter->name;
                $parameter->validation_rules = json_decode($parameter->validation_rules);
                $rules[$parameter->name] = $parameter->validation_rules;
            }
        }
        
        $request->validate($rules);
        $params = $request->only($params_name);
        $service_provider = Provider::where('id', $subscription->provider_id)->first();

        $params['proxy_id'] = $subscription->provider_service_id;
        if($user->role == "admin" && $request->parent_proxy_id)
            $params['parent_proxy_id'] = $request->parent_proxy_id;
        else        
            $params['parent_proxy_id'] = json_decode($subscription['data'])->parent_proxy_id;

        $providerClass = $service_provider->name;
        $provider = new $providerClass();
        $response = $provider->edit($params);
            
        if(is_array($response) && count($response) > 0)
        {
            $subscription->update([
                'expire_date'          => $request->expire_date?? $subscription->expire_date,
                'status'               => $request->status?? $subscription->status,
                'auto_renew'           => $request->auto_renew?? $subscription->auto_renew,
                'data'                 => json_encode($response),
            ]);

            return response()->json(new SubscriptionResource($subscription), 200);
        }
        else
            throw new BadRequestException('Subscription modification failed');
    }
```

```php
    public function cancel(Subscription $subscription)
    {
        $user = Auth::user();
        if($user->role == 'user'){
            if($subscription->user_id != $user->id)
                throw new BadRequestException('You do not have permissions to access this subscription');
        }
        
        $provider_id = $subscription->provider_id;
        $service_provider = Provider::find($provider_id);
        $providerClass = $service_provider->name;
        $provider = new $providerClass();
        $params['proxy_id'] = $subscription->provider_service_id;
        $response = $provider->cancel($params);

        if($response['result'] == true){
            $subscription->status = 'canceled';
            $subscription->save();
            return response()->json(new SubscriptionResource($subscription), 200);
        }
        else
            throw new BadRequestException('Unsubscribe failed');
    }
```

[🔝 Back to contents](#contents)