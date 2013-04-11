__license__ = "Python"
__copyright__ = "Copyright (C) 2007, Stephen Zabel"
__author__ = "Stephen Zabel - sjzabel@gmail.com"
__contributors__ = "Jay Parlar - parlar@gmail.com"

import logging, resource, time

from django.conf import settings
from django.http import HttpResponsePermanentRedirect, get_host

SSL = 'SSL'
KEEP_PROTOCOL = 'KEEP_PROTOCOL'

logger = logging.getLogger(__name__)

class SSLRedirect:

    def process_request(self, request):
        try:
            request.memory_usage = (resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024)
            request.start_time = time.time()
        except:
            pass

    def process_view(self, request, view_func, view_args, view_kwargs):
        if SSL in view_kwargs:
            secure = view_kwargs[SSL]
            del view_kwargs[SSL]
        else:
            secure = False

        if KEEP_PROTOCOL in view_kwargs:
            keep_protocol = view_kwargs[KEEP_PROTOCOL]
            del view_kwargs[KEEP_PROTOCOL]
        else:
            keep_protocol = False

        # Redirect to proper protocol unless we want to keep it
        if not keep_protocol and (not secure == self._is_secure(request)):
            return self._redirect(request, secure)

    def process_response(self, request, response):
        try:
            logger.debug('Memory used by request %s: %sMB, time elapsed: %.2f, user: %s' % (request.get_full_path(),
                                                                                            (resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024) - request.memory_usage,
                                                                                            (time.time() - request.start_time),
                                                                                            request.session.get('alusercache', 'unknown')))
            request.memory_usage = 0
        except:
            pass
        return response

    def _is_secure(self, request):
        if request.is_secure():
            return True

        #Handle the Webfaction case until this gets resolved in the request.is_secure()
        if 'HTTP_X_FORWARDED_SSL' in request.META:
            return request.META['HTTP_X_FORWARDED_SSL'] == 'on'

        return False

    def _redirect(self, request, secure):
        protocol = secure and "https" or "http"
        newurl = "%s://%s%s" % (protocol,get_host(request),request.get_full_path())
        if settings.DEBUG and request.method == 'POST':
            raise RuntimeError("""Django can't perform a SSL redirect while maintaining POST data.
           Please structure your views so that redirects only occur during GETs.""")

        return HttpResponsePermanentRedirect(newurl)
