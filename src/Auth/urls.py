# urls.py

from django.urls            import path
from Auth.views             import *

urlpatterns = [
    path('signup/', SignupAPIView.as_view(), name='signup'),
    path('signin/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('signout/', SignoutAPIView.as_view(), name='signout'),
    path('password/change/', ChangePasswordAPIView.as_view(), name='change_password'),
    path('password/reset/', PasswordResetAPIView.as_view(), name='reset_password'),
    path('password/reset/confirm/<uidb64>/<token>/', PasswordResetConfirmAPIView.as_view(), name='password_reset_confirm'),
    path('email/verification/request/', SendVerificationEmailAPIView.as_view(), name='send_verification_email'),
    path('email/verification/confirm/<uidb64>/<token>/', EmailVerificationConfirmAPIView.as_view(), name='verify_email'),
    path('otp/request/', OTPGenerateAPIView.as_view(), name='otp_verification'),
    path('otp/verify/', OTPVerificationAPIView.as_view(), name='email_verification'),
    path('token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshAPIView.as_view(), name='token_refresh')
]

app_name = 'auth'