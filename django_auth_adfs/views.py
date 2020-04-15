import base64
import inspect
import logging

from django.conf import settings as django_settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth import authenticate as algo, _get_backends
from django.shortcuts import redirect, render
from django.utils.http import is_safe_url
from django.views.generic import View

from django_auth_adfs.config import provider_config

logger = logging.getLogger("django_auth_adfs")


class OAuth2CallbackView(View):
    def get(self, request):
        """
        Handles the redirect from ADFS to our site.
        We try to process the passed authorization code and login the user.

        Args:
            request (django.http.request.HttpRequest): A Django Request object
        """
        code = request.GET.get("code")

        if not code:
            # Return an error message
            return render(request, 'django_auth_adfs/login_failed.html', {
                'error_message': "No authorization code was provided.",
            }, status=400)

        redirect_to = request.GET.get("state")

        user = authenticate(request=request, authorization_code=code)

        if user is not None:
            if user.is_active:
                login(request, user)
                # Redirect to the "after login" page.
                # Because we got redirected from ADFS, we can't know where the
                # user came from.
                if redirect_to:
                    redirect_to = base64.urlsafe_b64decode(redirect_to.encode()).decode()
                else:
                    redirect_to = django_settings.LOGIN_REDIRECT_URL
                url_is_safe = is_safe_url(
                    url=redirect_to,
                    allowed_hosts=[request.get_host()],
                    require_https=request.is_secure(),
                )
                redirect_to = redirect_to if url_is_safe else '/'
                return redirect(redirect_to)
            else:
                # Return a 'disabled account' error message
                return render(request, 'django_auth_adfs/login_failed.html', {
                    'error_message': "Your account is disabled.",
                }, status=403)
        else:
            # Return an 'invalid login' error message
            return render(request, 'django_auth_adfs/login_failed.html', {
                'error_message': "Login failed.",
            }, status=401)


class OAuth2LoginView(View):
    def get(self, request):
        """
        Initiates the OAuth2 flow and redirect the user agent to ADFS

        Args:
            request (django.http.request.HttpRequest): A Django Request object
        """
        return redirect(provider_config.build_authorization_endpoint(request))


class OAuth2LoginNoSSOView(View):
    def get(self, request):
        """
        Initiates the OAuth2 flow and redirect the user agent to ADFS

        Args:
            request (django.http.request.HttpRequest): A Django Request object
        """
        return redirect(provider_config.build_authorization_endpoint(request, disable_sso=True))


class OAuth2LoginNoSSOCustomView(View):
    
    def post(self, request):
        """
            Initiates the login flow and redirect the user

            Args:
                request (django.http.request.HttpRequest): A Django Request object
        """
        if request.POST:
            django_settings.LOGOUT_ADFS = False
            username = request.POST['username']
            password = request.POST['password']
            user = self.__verificate_user(request=request ,username=username, password=password)
            if user is not None:
                if user.is_active:
                    login(request, user)
                    return redirect(django_settings.LOGIN_REDIRECT_URL)
            else:
                return redirect(django_settings.LOGIN_REDIRECT_URL)
                return redirect(redirect_to)



    def __verificate_user(self, request=None, **credentials):
        """
            If the given credentials are valid, return a User object.
        """
        
        for backend, backend_path in _get_backends(return_tuples=True):
            # Only backend verified CustomerBackend
            if 'CustomerBackend' in backend_path:
                user = backend.authenticate(**credentials)
                if user is None:
                    break
                # Annotate the user object with the path of the backend.
                user.backend = backend_path
                return user
            else:
                break

class OAuth2LogoutView(View):
    def get(self, request):
        """
        Logs out the user from both Django and ADFS

        Args:
            request (django.http.request.HttpRequest): A Django Request object
        """
        logout(request)
        return redirect(provider_config.build_end_session_endpoint())
