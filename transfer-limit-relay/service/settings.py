"""
Django settings for service project.

Generated by 'django-admin startproject' using Django 2.0.2.

For more information on this file, see
https://docs.djangoproject.com/en/2.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/2.0/ref/settings/
"""

import os

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/2.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'b_31oxxpj%x00znw!msfnzt=r$ra9$a+6nl6$fdwm2+evcimtl'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = [
    '*'
]

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    'service.api',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'service.urls'

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

WSGI_APPLICATION = 'service.wsgi.application'

# Database
# https://docs.djangoproject.com/en/2.0/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': os.environ.get('DB_TYPE', 'django.db.backends.sqlite3'), #django.db.backends.postgresql_psycopg2
        'NAME': os.environ.get('DB_NAME', 'gnosis.db'),
        'USER': os.environ.get('DB_USER', ''),
        'PASSWORD': os.environ.get('DB_PASSWORD', ''),
        'HOST': os.environ.get('DB_HOST', ''),
        'PORT': os.environ.get('DB_PORT', ''),
    }
}

# Password validation
# https://docs.djangoproject.com/en/2.0/ref/settings/#auth-password-validators

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

# Internationalization
# https://docs.djangoproject.com/en/2.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/2.0/howto/static-files/

STATIC_URL = '/static/'

RELAY_ACCOUNT_PHRASE = os.environ.get('RELAY_ACCOUNT_PHRASE')
RELAY_SAFE_ADDRESS = os.environ.get('RELAY_SAFE_ADDRESS', None)
GAS_TOKEN_ADDRESS = os.environ.get('GAS_TOKEN_ADDRESS', '0x0000000000000000000000000000000000000000')
SAFE_RELAY_ENDPOINT = os.environ.get('SAFE_RELAY_ENDPOINT')
RPC_ENDPOINT = os.environ.get('RPC_ENDPOINT')
TRANSFER_LIMIT_MODULE = os.environ.get('TRANSFER_LIMIT_MODULE', "0x6039a26436bD08752215523FAd5A007Cd1702D5d")
ALLOWANCE_LIMIT_MODULE = os.environ.get('ALLOWANCE_LIMIT_MODULE', "0xfa546b1E598216c75D087D0b012ED978a726fB7d")
DEFAULT_GAS_PRICE = int(os.environ.get('DEFAULT_GAS_PRICE', '10000000000'))