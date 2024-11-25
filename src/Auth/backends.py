from django.contrib.auth            import get_user_model
from django.contrib.auth.backends   import ModelBackend


class MobileBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        # Return None if username or password is None
        if username is None or password is None:
            return None
        
        UserModel = get_user_model()

        try:
            # Check if the username is an email address
            if '@' in username:
                user = UserModel.objects.get(email=username)
            # Check if the username is a mobile number
            elif username.isdigit() and len(username) == 10:
                user = UserModel.objects.get(mobile=username)
            # If the username is neither an email address nor a mobile number, check if it's a username
            else:
                user = UserModel.objects.get(username=username)
        except UserModel.DoesNotExist:
            return None

        # Verify the password
        if user.check_password(password):
            return user
        return None

    def get_user(self, user_id):
        UserModel = get_user_model()
        try:
            return UserModel.objects.get(pk=user_id)
        except UserModel.DoesNotExist:
            return None
