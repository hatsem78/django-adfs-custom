import logging

import jwt
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import Group, User
from django.core.exceptions import ImproperlyConfigured, ObjectDoesNotExist, PermissionDenied

from django_auth_adfs import signals
from django_auth_adfs.config import provider_config, settings

logger = logging.getLogger("django_auth_adfs")
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission

UserModel = get_user_model()

class CustomerBackend(ModelBackend):
    """ Authenticate user by username or email """
    def authenticate(self, username=None, password=None):
        if username is None:
                username = kwargs.get(UserModel.USERNAME_FIELD)
        try:
            user = UserModel._default_manager.get_by_natural_key(username)
        except UserModel.DoesNotExist:
            # Run the default password hasher once to reduce the timing
            # difference between an existing and a nonexistent user (#20760).
            UserModel().set_password(password)
        else:
            if user.check_password(password) and self.user_can_authenticate(user):
                return user

    def get_user(self, user_id=None):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None