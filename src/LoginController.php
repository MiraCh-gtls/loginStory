<?php

namespace GTLS\LoginStory;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;


class LoginClass
{
    /**
     * Handle a login request to the application.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\RedirectResponse
     */
    public function index(){
        $data = (['status' => 200, 'message' => 'Logged in locally. Handle Azure AD login on frontend.']);
        return json_encode($data);
    }

    public function login(Request $request, $authProvider, $url, $sessionDomain)
    {
        $email = $request->input('Email');
        $password = $request->input('Password');

        $headers = [
            'Email' => $email,
            'Password' => $password,
        ];

        // Get an array of all the cookies
        $cookies = $_COOKIE;

        // Loop through each cookie and set it to expire
        foreach ($cookies as $name => $value) {
            setcookie($name, '', 1, '/', $sessionDomain, true);
        }
        $response = Http::withHeaders($headers)->get("$url" . "Login");
        if ($response->successful()) {
            $responseData = $response->json();
            if (!empty($responseData)) {
                // $authProvider = new CustomAuth();

                $credentials = [
                    'EmailInput' => $request->input('Email'),
                    'EmailDb' => $responseData[0]['Email'],
                    'PasswordDb' => $responseData[0]['UserId'],
                    'PasswordInput' => $request->input('Password'),
                ];

                $authenticatedUser = $authProvider->attempt($credentials, true);

                if ($authenticatedUser) {
                    // Redirect to the intended page with the obtained user
                    $user = null;
                    $TokenHeaders = [
                        'UserId'=> $responseData[0]['UserId'],
                        'OwnerId'=> $responseData[0]['OwnerId'],
                        // 'AppId'=> $appID,
                        'Content-Type'=> "application/x-www-form-urlencoded",
                    ];
                    $TokenBody = [
                        'grant_type' => "password",
                    ];

                    $tokenURL = $url;
                    $tokenRes = Http::withHeaders($TokenHeaders)
                    ->asForm()
                    ->post("$tokenURL" . "Token", $TokenBody);

                    // if($responseData[0]['TypeId'] == 1) // the user is a customer
                    // {
                    //     $user = new Customer($responseData[0]);
                    // }else if($responseData[0]['TypeId'] == 2) // the user is an employee
                    // {
                    //     $user = new Employee($responseData[0]);
                    // }
                    // else{ // the user is a driver
                    //     $user = new Driver($responseData[0]);
                    // }
                    if ($tokenRes->successful()) {
                        $token = $tokenRes->json();
                        $cookieName = 'access_token';
                        $cookieValue = $token['access_token'];
                        setcookie($name, '', 1, '/', $sessionDomain, true);
                        $userId = $user['UserId'];
                        $request->session()->regenerate();
                        $request->session()->put('user', $user);
                        $request->session()->put('user_id', $userId);
                        $request->session()->put('newRoute', '/loginapi');

                        $sessionId = $request->session()->getId();
                        $payload = $request->session()->get('_token');
                        $userSession = $request->session()->get('user');
                        $user = json_encode($userSession->getAttributes());

                        $lastActivity = time();
                        DB::table('custom_sessions')->insert([
                            'id' => $sessionId,
                            'user_id' => $userId,
                            'payload' => $payload,
                            'user' => $user,
                            'last_activity' => $lastActivity,
                            'created_at' => date("Y-m-d H:i:s"),
                            'updated_at' => date("Y-m-d H:i:s"),
                        ]);


                        $request->session()->save();
                        if ($request->session()->get('newRoute') && $request->session()->get('user')) {
                            return (['user'=> $user, 'request' => $request, 'status' => 200, 'message' => 'Login successful']);
                        }
                        }else{
                            $errorMessage = 'Something went wrong, try again later';
                            $statusCode = 500;
                            return (['user'=> null, 'request' => $request, 'status' => $statusCode, 'message' => $errorMessage]);
                        }


                } else {
                    $errorMessage = 'Invalid Credentials';
                    $statusCode = 500;
                    return (['user'=> null, 'request' => $request, 'status' => $statusCode, 'message' => $errorMessage]);
                }
            }
        } else {
            $errorMessage = 'Invalid Credentials';
            $statusCode = 500;
            return (['user'=> null, 'request' => $request, 'status' => $statusCode, 'message' => $errorMessage]);
        }
    }

    public function logout(Request $request, $user, $sessionDomain)
    {
        // Retrieve the 'access_token' cookie if available
        $token = $_COOKIE['access_token'] ?? null;
    
        // Create an instance of the RegisteredUserController and get the current user
        //$userController = new RegisteredUserController();
        //$user = $userController->getCurrentUserName($request);
        $userMsg = json_decode($user->content(), true);
    
        // If user data indicates 'User not found'
        if (isset($userMsg['message']) && $userMsg['message'] === 'User not found') {
            // Invalidate and flush session data
            $request->session()->invalidate();
            $request->session()->flush();
    
            // Clear cookies to log the user out fully
            $this->clearAllCookies($sessionDomain);
    
            // Regenerate the session token for security purposes
            $request->session()->regenerateToken();
    
            // Respond with success (Azure AD logout will be handled on the frontend)
            return (['status' => 200, 'message' => 'Logged out locally. Handle Azure AD logout on frontend.']);
        } else {
            // If user is found, proceed with API logout
            $UserId = $user->original['UserId'];
    
            // Set up headers for the API request
            $headers = [
                'UserId' => $UserId,
                'Authorization' => "Bearer " . $token,
            ];
    
            // Send the logout request to the external API
            $url = env('GTAM_API_URL') . "Logout";
            $response = Http::withHeaders($headers)->get($url);
    
            // Check if the logout request was successful
            if ($response->successful()) {
                // Invalidate and flush session data
                $request->session()->forget('user');
                $request->session()->invalidate();
                $request->session()->flush();
    
                // Clear cookies to log the user out fully
                $this->clearAllCookies($sessionDomain);
    
                // Regenerate the session token for security purposes
                $request->session()->regenerateToken();
    
                // Respond with success (Azure AD logout will be handled on the frontend)
                return (['status' => 200, 'message' => 'Logged out locally. Handle Azure AD logout on frontend.']);
            } else {
                // Handle failure in the external API call
                return (['status' => 500, 'message' => 'Logout failed. Please try again.']);
            }
        }
    }
    
    /**
     * Helper function to clear all cookies.
     */
    private function clearAllCookies($sessionDomain)
    {
        // Set the expiration time for the cookies to a past date (January 1, 1970)
        $expiration = time() - 3600;
    
        // Set domain and flags for cookie clearing
        $secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on';
    
        // Loop through each cookie and set it to expire
        foreach ($_COOKIE as $name => $value) {
            // Clear the cookie for all paths and domains
            setcookie($name, '', $expiration, '/', $sessionDomain, $secure, true); // Secure and HttpOnly flags
        }
    }
    
    public function logoutWithoutRequest(Request $request, $user, $sessionDomain)
    {
        // Retrieve the 'access_token' cookie
        $token = isset($_COOKIE['access_token']) ? $_COOKIE['access_token'] : null;

        // Create an instance of the RegisteredUserController and get the current user
        //$userController = new RegisteredUserController();
        //$user = $userController->getCurrentUserName($request);
        $userMsg = json_decode($user->getContent(), true);

        //check if user is not found
        if(gettype($userMsg) != "array" && gettype($userMsg) != "object" && gettype($userMsg) == "string") {
        if ($userMsg['message'] == 'User not found') {

                $request->session()->invalidate();
                $request->session()->flush();
                // Set the expiration time for the cookies to 1/1/1970
                $expiration = 1;
                $cookies = $_COOKIE;

                // Loop through each cookie and set it to expire
                foreach ($cookies as $name => $value) {
                    setcookie($name, '', $expiration, '/', $sessionDomain, true);
                }
                $request->session()->regenerateToken();
                // return redirect('/login');
        }} else {
                // Invalidate and flush the session
                $request->session()->forget('user');
                $request->session()->invalidate();
                $request->session()->flush();
                // Set the expiration time for the cookies to 1/1/1970
                $expiration = 1;

                // Get an array of all the cookies
                $cookies = $_COOKIE;

                // Loop through each cookie and set it to expire
                foreach ($cookies as $name => $value) {
                    setcookie($name, '', $expiration, '/', $sessionDomain, true);
                }

                // Regenerate the session token
                $request->session()->regenerateToken();
        }
    }

}
?>