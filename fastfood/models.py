from django.db import models

# Create your models here.
class Food(models.Model):
    name = models.CharField(max_length=100)
    ingredients = models.CharField(max_length=100)
    classification = models.CharField(max_length=20)
def __str__(self):
    return self.name