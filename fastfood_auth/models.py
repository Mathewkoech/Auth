from django.db import models
from django.contrib.auth.base_user import BaseUserManager, AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
from uuid import uuid4 as uuid
from django.conf import settings
from django.utils import timezone
from django.contrib.auth.models import User
from django.utils.translation import gettext_lazy as _
from common.models import FlaggedModelMixin, TimeStampedModelMixin
from django.contrib.postgres.fields import ArrayField
from django.contrib.auth.models  import Permission

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
    
class Role(TimeStampedModelMixin, FlaggedModelMixin):
    name = models.CharField(_('name'), max_length=150)
    permissions = models.ManyToManyField(
        Permission,
        verbose_name=_('permissions'),
        blank=True,
    )
    permission_list = ArrayField(
        models.CharField(max_length=100, blank=True, null=True), null=True, blank=True
    )

    class Meta:
        db_table = "roles"
        ordering = ["-created_at"]
        unique_together = "name"


class Permission(Permission):

    class Meta:
        proxy = True
    
class User(AbstractBaseUser):
    id = models.UUIDField(default=uuid, primary_key=True)
    first_name = models.CharField(("first name"), max_length=150, blank=True)
    last_name = models.CharField(("last name"), max_length=150, blank=True)
    username = models.CharField(("username"), max_length=150, blank=True, unique=True)
    email = models.EmailField(("email address"), blank=True, unique=True)
    phone = models.CharField(max_length=20, null=True, blank=True)
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True)
    modified_by = models.ForeignKey(
        "User",
        on_delete=models.SET_NULL,
        null=True,
        related_name="deleted_%(class)s",
    )
    AGENT = "agent"
    CUSTOMER = "customer"
    
    USER_CHOICES = (
       (AGENT, "agent"),
        (CUSTOMER, "customer")
    )
    user_type = models.CharField(
        ("user role"),
        max_length=20,
        blank=True,
        choices=USER_CHOICES,
        help_text=_(
            "Designates the role of the user in the system - For Authorization"
        ),
        default=CUSTOMER
    )
    role = models.ForeignKey("Role", on_delete=models.DO_NOTHING, null=True)
    is_staff = models.BooleanField(
        _("staff status"),
        default=False,
        help_text=_(
            "Designates whether the user can log into this admin site."
        ),
    )

    is_active = models.BooleanField(
        ("active"),
        default=True,
        help_text=_(
            "Designates whether this user should be treated as active. "
            "Unselect this instead of deleting accounts."
        ),
    )
    objects = MyUserManager()

    EMAIL_FIELD = "email"
    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = ['email', 'first_name', 'last_name']

    def _usable(self):
        return self.has_usable_password()

    _usable.boolean = True
    usable = property(_usable)

    @property
    def full_name(self):
        return "{0} {1}".format(self.first_name, self.last_name)

    def get_full_name(self):
        """
        Return the first_name plus the last_name, with a space in between.
        """
        full_name = "%s %s" % (self.first_name, self.last_name)
        return full_name.strip()

    def get_short_name(self):
        """Return the short name for the user."""
        return self.first_name

    def email_user(self, subject, message, from_email=None, **kwargs):
        """Send an email to this user."""
        send_mail(subject, message, from_email, [self.email], **kwargs)

    def _is_employee(self):
        return self.role == self.EMPLOYEE
    _is_employee.boolean = True
    is_employee = property(_is_employee)

    def _is_customer(self):
        return self.role == self.CUSTOMER
    _is_customer.boolean = True
    is_customer = property(_is_customer)

    def _is_supplier(self):
        return self.role == self.SUPPLIER
    _is_supplier.boolean = True
    is_supplier = property(_is_supplier)

    def _has_pin(self):
        if self.pin is None or self.pin == "":
            return False
        else:
            return True
    _has_pin.boolean = True
    has_pin = property(_has_pin)

    class Meta:
        db_table = "users"
        ordering = ["-date_joined"]