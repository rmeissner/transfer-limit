from django.db import models


class Credits(models.Model):
    account = models.CharField(max_length=42, primary_key=True)
    amount = models.BigIntegerField(default=0)
