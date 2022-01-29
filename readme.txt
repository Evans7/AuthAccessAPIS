Project description:-

->Users can signup using email, name and password
->Users can login using the email and password which would create a jwt token which holds the existing user roles as well
->User can view their own details using the jwt token
->Admin users can view all user details
->Admin users can add roles to user
->Admin users can view specific user details
->Users can view their own details

Run project:-
1. Pull project to local
2. Navigate to the directory
3. Run “pip3 install -r requirements.txt”
4. Run “python3 app.py”

Run test cases:-
1. Navigate into test_app.py 2. pass in jwt tokens for admin_token and user_token
3. pass user_id to add role to user.
4. Run “python3 -m unittest discover -p test_app.py”
