"""
HTTPie plugin to sign requests using Web Bot Auth for Ed25519 keys
"""

from bot_auth import BotAuth
from httpie.plugins import TransportPlugin
import json
import os
from requests.adapters import HTTPAdapter
import typing as t
from urllib.parse import urlparse, urlunparse

__version__ = "0.1.0"


class WebBotAuthAdapter(HTTPAdapter):
    def send(self, request: t.Any, **kwargs: t.Any) -> t.Any:
        """
        Intercepts the request, adds the signature header, and sends it.
        """
        # Key is provided in WBA_KEY env variable
        wba_key_path = os.getenv("WBA_KEY")
        if not wba_key_path:
            raise ValueError("WBA_KEY environment variable not set. Please set it to a path to your Ed25519 private key in JWK format.")

        if not os.path.isfile(wba_key_path):
            raise FileNotFoundError(f"WBA key file not found at {wba_key_path}")
        
        key = ""
        with open(wba_key_path, "r") as key_file:
            key = key_file.read()
        
        key = json.loads(key)

        wba = BotAuth(
            [key],
            signAgent="http-message-signatures-example.research.cloudflare.com",
        )
        parsed_url = urlparse(request.url)
        http_url_parts = parsed_url._replace(scheme='http')
        request.url = urlunparse(http_url_parts)

        headers = wba.get_bot_signature_header(request)

        # set extra headers
        for k, v in headers.items():
            request.headers[k] = v

        # Proceed with sending the request by calling the parent method
        return super().send(request, **kwargs)


class WebBotAuthPlugin(TransportPlugin):
    name = 'Web bot auth'
    description = 'Signs requests using Web Bot Auth for Ed25519 keys'
    prefix = 'http+wba://'

    def get_adapter(self):
        return WebBotAuthAdapter()
