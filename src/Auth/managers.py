from django.contrib.auth.base_user import BaseUserManager


class UserManager(BaseUserManager):
    def create_user(self, email, mobile, username, password=None):
        if not email:
            raise ValueError("Users must have an email address")

        if not username:
            raise ValueError("Users must have an unique username")
        
        if not mobile:
            raise ValueError("Users must have an unique mobile number")
        
        user = self.model(
            email=self.normalize_email(email),
            mobile=mobile,
            username=username,
        )
        user.set_password(password)
        user.is_staff = True
        user.is_superuser = True
        user.save()
        return user
    
    def create_superuser(self, email, mobile, username, password=None):
        user = self.create_user(
            email,
            mobile,
            username,
            password
        )
        user.is_staff = True
        user.is_superuser = True
        user.save()
        return user