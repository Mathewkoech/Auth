from django.db import models
from django.conf import settings
from uuid import uuid4 as uuid

# Create your models here.

class TimestampmodelMixin(models.Model):
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