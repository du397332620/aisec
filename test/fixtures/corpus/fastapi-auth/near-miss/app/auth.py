from app.config import AuthConfig


class AuthMiddleware:
    def __init__(self, app):
        self.app = app
        self.whitelist_paths = AuthConfig.whitelist_paths
        self.whitelist_prefixes = AuthConfig.whitelist_prefixes

    async def __call__(self, scope, receive, send):
        await self.app(scope, receive, send)
