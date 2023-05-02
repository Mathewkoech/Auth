from django.contrib import admin
from fastfood_auth.models import User
from django.contrib.auth.models import Permission


admin.site.register(User)
admin.site.register(Permission)