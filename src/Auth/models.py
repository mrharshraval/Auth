# models.py

# Base Imports
from datetime                   import timedelta
from django.core.mail           import send_mail
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.db                  import models
from django.shortcuts           import get_object_or_404
from django.utils               import timezone
from django.utils.translation   import activate, gettext_lazy as _

# App Based Imports
from Auth.managers              import UserManager


# Application url Import
from API.settings               import BASE_URL

from API.utils.generate         import GenerateOTP, GenerateUniqueKey, GenerateUniqueNumber
from API.utils.variables        import DEFAULT_ACTIVATION_MINUTES



# Custom user model
class User(AbstractBaseUser, PermissionsMixin):
    email           = models.EmailField(_('email address'), unique=True)
    username        = models.CharField(_('username'), max_length=32, unique=True, blank=True, null=True,)
    mobile          = models.CharField(_('mobile number'), max_length=10, unique=True, blank=True)
    date_joined     = models.DateTimeField(_('date joined'), auto_now_add=True)
    is_active       = models.BooleanField(_('active'), default=True)
    is_staff        = models.BooleanField(default=False)
    is_varified     = models.BooleanField(default=True)

    objects         = UserManager()

    USERNAME_FIELD  = 'username'
    REQUIRED_FIELDS = ['email', 'mobile']

    class Meta:
        verbose_name        = _('user')
        verbose_name_plural = _('users')


    def email_user(self, subject, message, from_email=None, **kwargs):
        # Sends an email to this user
        # send_mail(subject, message, from_email, [self.email], **kwargs)
        pass

    def get_user(self):
        return get_object_or_404(User, id__iexact=self.kwargs.get('pk'))




class OTP(models.Model):
    user            = models.ForeignKey(User, on_delete=models.CASCADE)
    otp             = models.CharField(max_length=6)
    created_at      = models.DateTimeField(auto_now_add=True)
    expired_at      = models.DateTimeField()
    is_verified     = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        if not self.expired_at:
            self.expired_at = timezone.now() + timedelta(minutes=5)
        
        if not self.pk:
            OTP.objects.filter(user=self.user, is_verified=False).delete()
        
        super().save(*args, **kwargs)

    def is_expired(self):
        return timezone.now() > self.expired_at

    def generate_otp(self):
        self.otp = GenerateOTP()
        self.save()

    def __str__(self):
        return f"OTP for {self.user.email}"