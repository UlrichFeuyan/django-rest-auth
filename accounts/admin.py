from django.contrib import admin
from .models import User, OneTimePassword

admin.site.register(User)
admin.site.register(OneTimePassword)
