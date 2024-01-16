#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

# Check if the user is logged in before each request
@app.before_request
def check_if_logged_in():
    open_access_list = [
        'signup',
        'login',
        'check_session'
    ]

    if (request.endpoint) not in open_access_list and (not session.get('user_id')):
        return {'error': '401 Unauthorized'}, 401

# Resource for user signup
class Signup(Resource):
    
    def post(self):
        # Get user information from the request JSON
        request_json = request.get_json()
        username = request_json.get('username')
        password = request_json.get('password')
        image_url = request_json.get('image_url')
        bio = request_json.get('bio')

        # Create a new User instance
        user = User(
            username=username,
            image_url=image_url,
            bio=bio
        )

        # Set the encrypted password using the setter method
        user.password_hash = password

        try:
            # Add the user to the database
            db.session.add(user)
            db.session.commit()

            # Set the user_id in the session for authentication
            session['user_id'] = user.id

            # Return user details and HTTP status code 201 (Created)
            return user.to_dict(), 201

        except IntegrityError:
            # Return an error if user creation fails due to integrity violation
            return {'error': '422 Unprocessable Entity'}, 422

# Resource to check the current session
class CheckSession(Resource):

    def get(self):
        user_id = session['user_id']
        if user_id:
            user = User.query.filter(User.id == user_id).first()
            # Return user details and HTTP status code 200 (OK)
            return user.to_dict(), 200
        
        # Return an empty response and HTTP status code 401 (Unauthorized)
        return {}, 401

# Resource for user login
class Login(Resource):
    
    def post(self):
        # Get login information from the request JSON
        request_json = request.get_json()
        username = request_json.get('username')
        password = request_json.get('password')

        # Query the database for the user with the provided username
        user = User.query.filter(User.username == username).first()

        if user:
            if user.authenticate(password):
                # Set the user_id in the session for authentication
                session['user_id'] = user.id
                # Return user details and HTTP status code 200 (OK)
                return user.to_dict(), 200

        # Return an error and HTTP status code 401 (Unauthorized) if login fails
        return {'error': '401 Unauthorized'}, 401

# Resource for user logout
class Logout(Resource):

    def delete(self):
        # Clear the user_id from the session
        session['user_id'] = None
        # Return an empty response and HTTP status code 204 (No Content)
        return {}, 204

# Resource for managing user's recipes
class RecipeIndex(Resource):

    def get(self):
        # Query the database for the user's recipes
        user = User.query.filter(User.id == session['user_id']).first()
        # Return a list of recipes in JSON format and HTTP status code 200 (OK)
        return [recipe.to_dict() for recipe in user.recipes], 200
        
    def post(self):
        # Get recipe information from the request JSON
        request_json = request.get_json()
        title = request_json['title']
        instructions = request_json['instructions']
        minutes_to_complete = request_json['minutes_to_complete']

        try:
            # Create a new Recipe instance
            recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user_id=session['user_id'],
            )

            # Add the recipe to the database
            db.session.add(recipe)
            db.session.commit()

            # Return recipe details and HTTP status code 201 (Created)
            return recipe.to_dict(), 201

        except IntegrityError:
            # Return an error if recipe creation fails due to integrity violation
            return {'error': '422 Unprocessable Entity'}, 422

# Add resources to the API with corresponding endpoints
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')

# Run the Flask app if the script is executed
if __name__ == '__main__':
    app.run(port=5555, debug=True)
