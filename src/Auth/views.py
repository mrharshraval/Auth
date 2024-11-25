# views.py

from rest_framework.views               import APIView
from rest_framework.response            import Response
from rest_framework                     import status
from rest_framework.permissions         import IsAuthenticated, AllowAny
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens    import RefreshToken, OutstandingToken, BlacklistedToken
from rest_framework_simplejwt.views     import TokenObtainPairView, TokenRefreshView, TokenBlacklistView

from django.contrib.auth                import authenticate, login, logout
from django.contrib.auth.tokens         import default_token_generator
from django.core.mail                   import send_mail
from django.utils                       import timezone
from django.utils.encoding              import force_bytes
from django.utils.http                  import urlsafe_base64_encode, urlsafe_base64_decode
from django.urls                        import reverse
from django.contrib                     import messages

from Auth.serializers                   import *


class SignupAPIView(APIView):
    permission_classes = [AllowAny]  # Allow unauthenticated access to this view

    def post(self, request):
        serializer = CreateUserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class SignoutAPIView(TokenBlacklistView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            # You can blacklist the current user’s token (ensure JWT Blacklisting is enabled in settings)
            token = request.auth  # Get the token from the request (authorization header)

            OutstandingToken.objects.filter(token=token).delete()  # Remove the outstanding token from DB (optional)
            BlacklistedToken.objects.create(token=token)  # Blacklist the token
            return Response({"detail": "Successfully signed out."}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"detail": "Error occurred during sign out."}, status=status.HTTP_400_BAD_REQUEST)
        

class ChangePasswordAPIView(APIView):
    """
    API view for changing user password.
    """
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({'success': True}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetAPIView(APIView):
    """
    API view for requesting a password reset.
    """
    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = User.objects.get(email=email)
            token = default_token_generator.make_token(user)
            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
            reset_url = request.build_absolute_uri(reverse('password_reset_confirm', kwargs={'uidb64': uidb64, 'token': token}))

            # Send password reset email
            send_mail(
                'Password Reset Request',
                f'Click the link to reset your password: {reset_url}',
                'from@example.com',
                [email],
                fail_silently=False,
            )
            return Response({'message': 'Password reset email sent.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetConfirmAPIView(APIView):
    """
    API view for confirming a password reset.
    """
    def post(self, request, uidb64, token):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            try:
                uid = urlsafe_base64_decode(uidb64).decode()
                user = User.objects.get(pk=uid)
            except (TypeError, ValueError, OverflowError, User.DoesNotExist):
                return Response({'error': 'Invalid reset link'}, status=status.HTTP_400_BAD_REQUEST)

            if not default_token_generator.check_token(user, token):
                return Response({'error': 'Invalid reset link'}, status=status.HTTP_400_BAD_REQUEST)

            user.set_password(serializer.validated_data['password'])
            user.save()
            return Response({'message': 'Password has been reset.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SendVerificationEmailAPIView(APIView):
    """
    API view for sending a verification email.
    """
    def post(self, request):
        serializer = EmailVerificationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.send_verification_email()
            return Response({"message": "Verification email sent."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EmailVerificationConfirmAPIView(APIView):
    """
    API view for confirming email verification.
    """
    def get(self, request, uidb64, token):
        serializer = EmailVerificationConfirmSerializer(data={'uidb64': uidb64, 'token': token})
        if serializer.is_valid():
            return Response({"message": "Email verified successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class OTPVerificationAPIView(APIView):
    """
    API view for verifying OTP.
    """
    def post(self, request):
        serializer = OTPVerificationSerializer(data=request.data)
        if serializer.is_valid():
            return Response({"message": "OTP verified successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class OTPGenerateAPIView(APIView):
    """
    API view for generating and sending OTP.
    """
    def post(self, request):
        email = request.data.get("email")

        try:
            user = User.objects.get(email=email)
            otp_instance = GenerateOTP(user=user)
            otp_instance.send_otp()  # Assuming `send_otp` is a method that emails the OTP to the user
            return Response({"message": "OTP sent successfully."}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "User with this email does not exist."}, status=status.HTTP_400_BAD_REQUEST)
        
class CustomTokenObtainPairView(TokenObtainPairView):
    """
    Custom token obtain pair view for JWT token authentication.
    """
    serializer_class = CustomTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except ValidationError as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.validated_data.get('user')
        if not user:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)

        return Response({
            'access_token': access_token,
            'refresh_token': refresh_token
        }, status=status.HTTP_200_OK)


class TokenRefreshAPIView(APIView):
    """
    API view for refreshing JWT token.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        refresh_token = request.data.get('refresh_token')
        if not refresh_token:
            return Response({'error': 'Refresh token is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            refresh = RefreshToken(refresh_token)
            access_token = str(refresh.access_token)
            return Response({'access_token': access_token}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_401_UNAUTHORIZED)
        