"""service URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.urls import path

from service.api.views import execute_limit_transfer, get_limit, get_allowance, submit_instant_transfer

urlpatterns = [
    path('api/1/safes/<str:safe>/tokens/<str:token>/execute_limit_transfer', execute_limit_transfer),
    path('api/1/safes/<str:safe>/tokens/<str:token>/get_limit', get_limit),

    path('api/1/safes/<str:safe>/delegates/<str:delegate>/tokens/<str:token>/submit_instant_transfer', submit_instant_transfer),
    path('api/1/safes/<str:safe>/delegates/<str:delegate>/tokens/<str:token>/allowance', get_allowance),
]
