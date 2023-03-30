from django.db import models
from django.contrib.auth.base_user import BaseUserManager, AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
from uuid import uuid4 as uuid
# Create your models here.



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
    
class User(models.Model):
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

