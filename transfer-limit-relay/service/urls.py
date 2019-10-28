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

from service.api.views import execute_tx_subscription, execute_tx_credits, redeem_voucher, check_balance, \
    estimate_tx_credits

urlpatterns = [
    path('api/1/execute_tx', execute_tx_subscription),
    path('api/2/execute_tx', execute_tx_credits),
    path('api/1/estimate_tx', estimate_tx_credits),
    path('api/1/redeem', redeem_voucher),
    path('api/1/balance', check_balance)
]
