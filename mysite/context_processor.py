from .settings import LOGOUT_ADFS

def global_vars(request):

    return {
        "LOGOUT_ADFS": LOGOUT_ADFS,
    }
