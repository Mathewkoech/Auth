from django.db import models
from django.conf import settings
from uuid import uuid4 as uuid

# Create your models here.

class TimeStampedModelMixin(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    modified_at = models.DateTimeField(auto_now=True, null=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="created_%(class)s",
    )
    modified_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="modified_%(class)s",
    )

class Meta:
        abstract = True
        indexes = [models.Index(fields=["-created_at"])]

def __str__(self):
        if hasattr(self, "name"):
            return self.name
        return str(self.id)

class FlaggedModelMixin(models.Model):
    """
    This abstract model contains shared functionality pertaining to
    flag-enabled fields in a model.
    These fields are:
    - is_deleted: this is marks the model instance as deleted, instead of
    physically deleting.
    - deleted_at: this goes hand in hand with `is_deleted`.
    Gives the timestamp when an object is marked as deleted.
    - is_active: this is marks the instance as active
    """

    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True)

    class Meta:
        abstract = True
        indexes = [
            models.Index(fields=["is_active"]),
            models.Index(fields=["is_deleted"]),
        ]