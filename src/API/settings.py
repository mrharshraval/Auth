import os
from pathlib                    import Path
from datetime                   import timedelta


# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent




# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.getenv('SECRET_KEY', 'fj23lj-dafdk1l3-&n46*&q+%l!gh&nn!_qukn(99wi5p*-s_-v762$ojq*!w8&$u*')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []


# Front-end url 
FRONTEND_URL            = "http://localhost:8000"



# Email Service 
EMAIL_BACKEND           = 'django.core.mail.backends.smtp.EmailBackend'
# EMAIL_HOST              = 'localhost'
# EMAIL_PORT              = 1025  # Default MailHog SMTP port
# EMAIL_USE_TLS           = False
# DEFAULT_FROM_EMAIL      = 'webmaster@localhost'

HTTP_PORT               = ':8000'
BASE_URL                = 'http://127.0.0.1' + HTTP_PORT


# Application definition


INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',           # Django REST Framework
    'rest_framework_simplejwt.token_blacklist', # JWT for token-based authentication
    'corsheaders',              # CORS headers for cross-origin requests

    'Auth'
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'API.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'API.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.1/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


# Password validation
# https://docs.djangoproject.com/en/5.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Authentication Backends
AUTHENTICATION_BACKENDS = (
    'django.contrib.auth.backends.ModelBackend',
    'Auth.backends.MobileBackend',
)



# Custom Authentication Backend for site [User]
AUTH_USER_MODEL = 'Auth.User'



# Internationalization
# https://docs.djangoproject.com/en/5.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.1/howto/static-files/

STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/5.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'



# Django REST Framework Configuration
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.BasicAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',  # Default to authenticated access
    )
}

# Simple JWT Configuration
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME'     : timedelta(minutes=60),    # Customize the access token expiry time
    'REFRESH_TOKEN_LIFETIME'    : timedelta(days=15),       # Customize the refresh token expiry time
    'ROTATE_REFRESH_TOKENS'     : True,                     # Issue a new refresh token each time one is used
    'BLACKLIST_AFTER_ROTATION'  : True,                     # Blacklist used refresh tokens
    'ALGORITHM'                 : 'HS256',                  # Default algorithm for JWT
    'SIGNING_KEY'               : SECRET_KEY,               # Replace with a strong secret key
    'AUTH_HEADER_TYPES'         : ('Bearer',),              # The header type used in the JWT Authorization header
}


# Allow all domains (use only for development, not recommended for production)
CORS_ALLOW_ALL_ORIGINS = True

# OR allow only specific origins (use this in production)
# CORS_ALLOWED_ORIGINS = [
#     "http://localhost:8000",  # Auth API URL
#     "http://localhost:8080",  # Products API URL
# ]

# Allow all HTTP methods (GET, POST, PUT, DELETE, etc.)
CORS_ALLOW_METHODS = [
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "OPTIONS",
    "PATCH",
]

# Allow specific headers in requests
CORS_ALLOW_HEADERS = [
    "authorization",
    "content-type",
]

# Optionally, you can allow credentials to be included in cross-origin requests
CORS_ALLOW_CREDENTIALS = True