# serializers.py
from rest_framework                         import serializers
from rest_framework_simplejwt.serializers   import TokenObtainPairSerializer

from django.contrib.auth                    import get_user_model, password_validation, authenticate
from django.contrib.auth.forms              import PasswordResetForm
from django.contrib.auth.tokens             import default_token_generator
from django.core.exceptions                 import ValidationError
from django.core.mail                       import send_mail
from django.urls                            import reverse
from django.utils                           import timezone
from django.utils.http                      import urlsafe_base64_decode
from django.utils.translation               import gettext_lazy as _
from django.utils.encoding                  import force_bytes, force_str
from django.utils.http                      import urlsafe_base64_encode, urlsafe_base64_decode
from django.conf                            import settings



from Auth.models                            import User, OTP
from API.utils.generate                     import GenerateOTP



# Serializer for user details
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'mobile', 'is_varified', 'is_active']



class CreateUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True, required=True, style={'input_type': 'password'},
        help_text=_("Must contain at least 8 characters, including letters and numbers.")
    )
    password2 = serializers.CharField(
        write_only=True, required=True, style={'input_type': 'password'}
    )

    class Meta:
        model = User
        fields = ['id', 'email', 'username', 'mobile', 'password', 'password2']
    
    def validate(self, data):
        # Check if passwords match
        if data['password'] != data['password2']:
            raise ValidationError({"password2": _("The two passwords must match.")})
        return data

    def validate_password(self, value):
        # Enforce password complexity and catch validation errors
        try:
            password_validation.validate_password(value, self.instance)
        except ValidationError as e:
            raise ValidationError({"password": e.messages})
        return value

    def create(self, validated_data):
        # Remove password2 as it's not needed in the User model
        validated_data.pop('password2')
        
        # Create user and hash the password
        user = User.objects.create_user(**validated_data)
        
        return user

    def to_representation(self, instance):
        # Customize response data for successful registration
        response = super().to_representation(instance)
        return {
            "id": response['id'],
            "email": response['email'],
            "username": response['username'],
        }


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True, style={'input_type': 'password'})
    new_password = serializers.CharField(required=True, style={'input_type': 'password'})
    confirm_new_password = serializers.CharField(required=True, style={'input_type': 'password'})

    def validate(self, data):
        if data['new_password'] != data['confirm_new_password']:
            raise serializers.ValidationError(_("The new passwords do not match."))
        return data
    
    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError(_("Incorrect old password."))
        return value
    
    def validate_new_password(self, value):
        # Validate password complexity
        password_validation.validate_password(value)
        return value
    
    def save(self):
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()
        return user

class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        """
        Validate that the email exists in the system.
        """
        form = PasswordResetForm({'email': value})
        if not form.is_valid():
            raise serializers.ValidationError(_("No user found with this email."))
        return value

class PasswordResetConfirmSerializer(serializers.Serializer):
    uidb64 = serializers.CharField()
    token = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        """
        Validate that the uidb64 is valid and the token is valid for the user.
        """
        uidb64 = data.get('uidb64')
        token = data.get('token')
        password = data.get('password')

        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None
        
        if user is None or not default_token_generator.check_token(user, token):
            raise serializers.ValidationError(_("Invalid reset link."))
        
        return data



class EmailVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        """
        Check if the user with this email exists and is not verified yet.
        """
        try:
            user = User.objects.get(email=value)
            if user.is_verified:
                raise serializers.ValidationError("This account is already verified.")
            self.user = user  # Store the user for use in send_verification_email()
        except User.DoesNotExist:
            raise serializers.ValidationError("No user is associated with this email.")
        return value

    def send_verification_email(self):
        """
        Send an email with a verification link to the user.
        """
        user = self.user
        token = default_token_generator.make_token(user)
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        verification_url = reverse('verify_email', kwargs={'uidb64': uidb64, 'token': token})
        full_url = f"{settings.FRONTEND_URL}{verification_url}"

        send_mail(
            'Verify your email',
            f'Click the link to verify your email: {full_url}',
            'from@example.com',
            [user.email],
            fail_silently=False,
        )
        return True


class EmailVerificationConfirmSerializer(serializers.Serializer):
    uidb64 = serializers.CharField()
    token = serializers.CharField()

    def validate(self, data):
        """
        Validate the UID and token, confirming the user if valid.
        """
        uidb64 = data.get('uidb64')
        token = data.get('token')

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError("Invalid user or UID.")

        if not default_token_generator.check_token(user, token):
            raise serializers.ValidationError("Invalid or expired token.")

        # Mark the user as verified
        user.is_verified = True
        user.save()

        return data


class OTPVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)

    def validate(self, data):
        email = data.get('email')
        otp_code = data.get('otp')

        try:
            # Retrieve the user based on email
            user = User.objects.get(email=email)
            
            # Retrieve the latest unverified OTP for the user
            otp = OTP.objects.filter(user=user, otp=otp_code, is_verified=False).latest('created_at')

            # Check if OTP has expired
            if otp.is_expired():
                raise serializers.ValidationError(_("OTP has expired."))

            # Mark OTP as verified and update user verification status
            otp.is_verified = True
            otp.save()
            user.is_verified = True
            user.save()

        except User.DoesNotExist:
            raise serializers.ValidationError(_("User with this email does not exist."))
        except OTP.DoesNotExist:
            raise serializers.ValidationError(_("Invalid OTP or OTP not found."))

        return data


# Signin : Custom Token Obtain Pair Serializer
class CustomTokenObtainPairSerializer(serializers.Serializer):
    """
    Serializer for obtaining the token pair.
    """
    identifier = serializers.CharField(required=True)
    password = serializers.CharField(
        max_length=128,
        write_only=True,
        style={'input_type': 'password'}
    )

    def validate(self, attrs):
        """
        Validate the username and password.
        """
        identifier = attrs.get('identifier')
        password = attrs.get('password')

        if not identifier or not password:
            raise serializers.ValidationError(_("Must include both 'username' and 'password'."))

        # Check if the username is email
        if '@' in identifier:
            # Attempt to authenticate with email
            user = authenticate(request=self.context.get('request'), email=identifier, password=password)
        else:
            # Attempt to authenticate with username
            user = authenticate(request=self.context.get('request'), username=identifier, password=password)
            if not user:
                # Attempt to authenticate with mobile number
                user = authenticate(request=self.context.get('request'), mobile=identifier, password=password)

        if user is None:
            raise serializers.ValidationError(_("Unable to log in with provided credentials."))

        if not user.is_active:
            raise serializers.ValidationError(_("User account is disabled."))

        attrs['user'] = user
        return attrs
