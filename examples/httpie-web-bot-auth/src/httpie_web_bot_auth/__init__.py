"""
HTTPie plugin to sign requests using Web Bot Auth for Ed25519 keys
"""

from bot_auth import BotAuth
from httpie.plugins import TransportPlugin
import json
import os
from requests.adapters import HTTPAdapter
from requests import HTTPError, Response
import typing as t
from urllib.parse import urljoin, urlparse, urlunparse

__version__ = "0.1.0"


def _check_redirect(response: Response, **kwargs: object) -> Response:
    if response.is_redirect:
        origins = []
        for url in (response.url, urljoin(response.url, response.headers["Location"])):
            parsed = urlparse(url)
            port = parsed.port
            if port is None:
                port = {"http": 80, "https": 443}.get(parsed.scheme)
            origins.append((parsed.scheme, parsed.hostname, port))
        if origins[0] != origins[1]:
            raise HTTPError(
                "Web Bot Auth blocks cross-origin redirects to protect signatures",
                response=response,
            )
    return response


class WebBotAuthAdapter(HTTPAdapter):
    def send(self, request: t.Any, **kwargs: t.Any) -> t.Any:
        """
        Intercepts the request, adds the signature header, and sends it.
        """
        # Key is provided in HTTPIE_WBA_KEY env variable
        wba_key_path = os.getenv("HTTPIE_WBA_KEY")
        if not wba_key_path:
            raise ValueError(
                "HTTPIE_WBA_KEY environment variable not set. Please set it to a path to your Ed25519 private key in JWK format."
            )

        with open(wba_key_path, "r") as key_file:
            key = json.load(key_file)

        wba = BotAuth(
            [key],
            signAgent=(
                request.headers.get("Signature-Agent").decode("utf-8")
                if request.headers.get("Signature-Agent")
                else None
            ),
        )
        parsed_url = urlparse(request.url)
        http_url_parts = parsed_url._replace(
            scheme="http" if parsed_url.scheme in ["http", "http+wba"] else "https"
        )
        request.url = urlunparse(http_url_parts)

        headers = wba.get_bot_signature_header(request.url)

        # set extra headers
        for k, v in headers.items():
            request.headers[k] = v

        request.register_hook("response", _check_redirect)

        # Proceed with sending the request by calling the parent method
        return super().send(request, **kwargs)


class WebBotAuthHTTPPlugin(TransportPlugin):
    name = "Web bot auth HTTP"
    description = "Signs HTTP requests using Web Bot Auth for Ed25519 keys"
    prefix = "http+wba://"

    def get_adapter(self):
        return WebBotAuthAdapter()


class WebBotAuthHTTPSPlugin(TransportPlugin):
    name = "Web bot auth HTTPS"
    description = "Signs HTTP requests using Web Bot Auth for Ed25519 keys"
    prefix = "https+wba://"

    def get_adapter(self):
        return WebBotAuthAdapter()
