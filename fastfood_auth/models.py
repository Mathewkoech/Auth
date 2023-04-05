from django.db import models
from django.contrib.auth.base_user import BaseUserManager, AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
from uuid import uuid4 as uuid
from django.conf import settings
from django.utils import timezone
from django.contrib.auth.models import User
from django.utils.translation import gettext_lazy

class MyUserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, username, email, first_name, last_name, password, **extra_fields):
        """
        Creates and saves a user with the given password and email
        """
        if not email:
            raise ValueError("The given email must be set")
        email = self.normalize_email(email)
        if not username:
            raise ValueError("The given username must be set")
        user = self.model(username=username, email=email, first_name=first_name, last_name=last_name, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_user(self,username,password=None,email= None,first_name = None,last_name = None,**extra_fields):
        return self._create_user(username,email,password,first_name,last_name,**extra_fields)
    
    def create_superuser(self,username,email,password,first_name,last_name,**extra_fields):
        extra_fields.setdefault("is_superuser", True)
        
        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("superuser must be is_superuser = True.")
        return self ._create_user(username,email,password,first_name,last_name,**extra_fields)
    
class User(AbstractBaseUser):
    id = models.UUIDField(default=uuid, primary_key=True)
    first_name = models.CharField(("first name"), max_length=150, blank=True)
    last_name = models.CharField(("last name"), max_length=150, blank=True)
    username = models.CharField(("username"), max_length=150, blank=True, unique=True)
    email = models.EmailField(("email address"), blank=True, unique=True)
    phone = models.CharField(max_length=20, null=True, blank=True)
    pin = models.CharField(max_length=255, null=True, blank=True)
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True)
    modified_by = models.ForeignKey(
        "User",
        on_delete=models.SET_NULL,
        null=True,
        related_name="deleted_%(class)s",
    )
    objects = MyUserManager()

    EMAIL_FIELD = "email"
    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = ['email', 'first_name', 'last_name']

    def _usable(self):
        return self.has_usable_password()

    _usable.boolean = True
    usable = property(_usable)