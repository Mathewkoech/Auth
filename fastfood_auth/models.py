from django.db import models
from django.contrib.auth.base_user import BaseUserManager, AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
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
    
Class User():
