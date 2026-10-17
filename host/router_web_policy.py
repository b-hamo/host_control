"""Operator-owned web access policy, independent of command execution grants."""
import re
from urllib.parse import urlsplit


class WebScopeError(ValueError):
    """Safe, structured policy denial; never echo URL credentials or queries."""
    def __init__(self, code, operation, origins, origin=None):
        super().__init__(code)
        self.body = {'ok': False, 'error': code, 'operation': operation,
                     'requested_origin': origin, 'allowed_origins': sorted(origins),
                     'message': ('Only valid HTTP(S) URLs without credentials are permitted.'
                                 if code == 'INVALID_WEB_URL' else 'This origin is outside the user task access scope.'),
                     'recommended_next_step': 'Update the Host task file from the user request, then stop the current task before starting new work.'}


class WebPolicy:
    def __init__(self, origins, mode='scoped'):
        if mode not in {'scoped', 'web'}:
            raise ValueError('Invalid browsing policy')
        self.mode = mode
        self.origins = frozenset(origins)

    @staticmethod
    def origin(url):
        if not isinstance(url, str) or re.search(r'[\s\\\x00-\x1f\x7f]', url):
            raise ValueError('Invalid web URL')
        p = urlsplit(url)
        if p.scheme not in {'http', 'https'} or not p.hostname or p.username is not None or p.password is not None:
            raise ValueError('Only HTTP(S) URLs without credentials are allowed')
        port = p.port  # Reject malformed/out-of-range ports before browser dispatch.
        host = p.hostname.encode('idna').decode('ascii').lower()
        if ':' in host:
            host = '[' + host + ']'
        default = 443 if p.scheme == 'https' else 80
        return f'{p.scheme}://{host}' + (f':{port}' if port is not None and port != default else '')

    def allowed(self, url):
        try:
            origin = self.origin(url)
            return self.mode == 'web' or any(origin == self.origin(item) for item in self.origins)
        except (ValueError, UnicodeError):
            return False

    def require(self, url, operation):
        try:
            origin = self.origin(url)
        except (ValueError, UnicodeError):
            raise WebScopeError('INVALID_WEB_URL', operation, self.scope) from None
        if not self.allowed(url):
            raise WebScopeError('WEB_SCOPE_DENIED', operation, self.scope, origin)
        return origin

    @property
    def scope(self):
        return ('http://*', 'https://*') if self.mode == 'web' else tuple(sorted(self.origins))
