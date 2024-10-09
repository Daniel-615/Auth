from django.db import models
import uuid
from django.contrib.auth.models import AbstractUser, Group, Permission

class Usuario(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    token = models.CharField(max_length=50, null=False, blank=False)
    username = models.CharField(max_length=30, unique=True, null=False, blank=False)  # unique=True para evitar duplicados
    groups = models.ManyToManyField(
        Group,
        related_name='usuarios',
        blank=True
    )
    user_permissions = models.ManyToManyField(
        Permission,
        related_name='usuarios',
        blank=True
    )

    def __str__(self):
        return f'Usuario creado: {self.username}'
