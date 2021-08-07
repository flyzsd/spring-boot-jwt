
## Testing Authorization Code Flow
- Browse to http://localhost:9000/oauth2/authorize?grant_type=authorization_code&response_type=code&client_id=messaging-client&scope=read&state=1234
- The application, if the user is not logged in, redirects to the login page, at http://localhost:9000/login
- Once the user logs in, the application generates a code and redirects to the registered redirect URI with code
- You can get oauth2 token using http://localhost:9000/oauth2/token?grant_type=authorization_code&code=...