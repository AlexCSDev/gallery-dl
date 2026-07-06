# -*- coding: utf-8 -*-

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.

"""curl_cffi.requests.Session wrapped with a requests.Session
-compatible API for browser TLS fingerprint impersonation."""

from http.client import responses as HTTP_STATUS_PHRASES
import requests.exceptions

try:
    import curl_cffi.requests
    import curl_cffi.requests.exceptions as _cexc
except ImportError:
    curl_cffi = None
    _cexc = None


def _wrap_request(func, *args, **kwargs):
    try:
        return func(*args, **kwargs)
    except Exception as exc:
        if _cexc is None:
            raise
        if isinstance(exc, _cexc.ConnectionError):
            raise requests.exceptions.ConnectionError(
                exc) from exc
        if isinstance(exc, _cexc.Timeout):
            raise requests.exceptions.Timeout(exc) from exc
        if isinstance(exc, _cexc.ContentDecodingError):
            raise requests.exceptions.ContentDecodingError(
                exc) from exc
        if isinstance(exc, _cexc.ChunkedEncodingError):
            raise requests.exceptions.ChunkedEncodingError(
                exc) from exc
        if isinstance(exc, _cexc.RequestException):
            raise requests.exceptions.RequestException(
                exc) from exc
        raise


class CurlCffiResponseWrapper():

    def __init__(self, response):
        self._response = response

    def __getattr__(self, name):
        return getattr(self._response, name)

    @property
    def reason(self):
        r = self._response.reason
        if r:
            return r
        return HTTP_STATUS_PHRASES.get(
            self._response.status_code, "")


class CookieJarWrapper():
    # Delegates iteration to the underlying http.cookiejar.CookieJar
    # so callers see Cookie objects with .name/.domain/.expires
    # rather than the bare name strings curl_cffi.Cookies yields.

    def __init__(self, cffi_cookies):
        self._cookies = cffi_cookies

    @property
    def jar(self):
        return self._cookies.jar

    def __iter__(self):
        return iter(self._cookies.jar)

    def __bool__(self):
        return bool(list(self._cookies.jar))

    def __len__(self):
        return len(list(self._cookies.jar))

    def set_cookie(self, cookie):
        self._cookies.jar.set_cookie(cookie)

    def set(self, name, value, domain="", path="/"):
        self._cookies.set(
            name, value, domain=domain, path=path)


class CurlCffiSessionWrapper():

    def __init__(self, impersonate="firefox", proxy=None,
                 trust_env=True, session=None):
        if curl_cffi is None:
            raise ImportError(
                "curl_cffi is required but not installed. "
                "Install it with: pip install curl_cffi"
            )
        if session is not None:
            self._session = session
        else:
            self._session = curl_cffi.requests.Session(
                impersonate=impersonate,
            )
            if proxy:
                self._session.proxies = proxy
            self._session.trust_env = trust_env

        self.trust_env = trust_env
        self.headers = self._session.headers
        self.cookies = CookieJarWrapper(self._session.cookies)

    def request(self, method, url, **kwargs):
        # requests silently drops None-valued headers; curl_cffi
        # rejects them
        if "headers" in kwargs and kwargs["headers"]:
            kwargs["headers"] = {
                k: v for k, v in kwargs["headers"].items()
                if v is not None
            }
        response = _wrap_request(
            self._session.request, method, url, **kwargs)
        return CurlCffiResponseWrapper(response)

    def mount(self, prefix, adapter):
        """No-op — curl_cffi does not use adapters."""

    def close(self):
        self._session.close()
