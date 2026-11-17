import unittest
from unittest.mock import mock_open, patch

from requests import Response, Session

from httpie_web_bot_auth import WebBotAuthAdapter


class RedirectTests(unittest.TestCase):
    def test_redirects(self):
        for destinations, signed in (
            (("/next",), True),
            (("https://origin.test/next",), True),
            (("https://ORIGIN.test:443/next",), True),
            (("https://attacker.test/next",), False),
            (("//attacker.test/next",), False),
            (("https://origin.test:444/next",), False),
            (("https://origin.test:0/next",), False),
            (("http://origin.test/next",), False),
            (("/next", "https://attacker.test/next"), False),
            (("https://attacker.test/next", "/last"), False),
            (("https://attacker.test/next", "https://origin.test/back"), False),
        ):
            for follow in (False, True):
                with self.subTest(destinations=destinations, follow=follow):
                    sent = []

                    def send(adapter, request, **kwargs):
                        sent.append((request.url, dict(request.headers)))
                        response = Response()
                        response.request = request
                        response.url = request.url
                        response._content = b""
                        response.status_code = (
                            302 if len(sent) <= len(destinations) else 200
                        )
                        if response.status_code == 302:
                            response.headers["Location"] = destinations[len(sent) - 1]
                        return response

                    signatures = {
                        "Signature": "signed",
                        "Signature-Input": "input",
                        "Signature-Agent": "agent",
                    }
                    with (
                        Session() as session,
                        patch.dict("os.environ", {"HTTPIE_WBA_KEY": "key.json"}),
                        patch("builtins.open", mock_open(read_data="{}")),
                        patch("httpie_web_bot_auth.BotAuth") as signer,
                        patch("requests.adapters.HTTPAdapter.send", new=send),
                    ):
                        signer.return_value.get_bot_signature_header.return_value = (
                            signatures
                        )
                        session.trust_env = False
                        session.mount("https+wba://", WebBotAuthAdapter())
                        response = session.get(
                            "https+wba://origin.test/start", allow_redirects=follow
                        )
                        self.assertEqual(response.status_code, 200 if follow else 302)
                        self.assertEqual(
                            len(sent), len(destinations) + 1 if follow else 1
                        )
                        if not follow:
                            self.assertEqual(
                                response.headers["Location"], destinations[0]
                            )
                        for header, value in signatures.items():
                            self.assertEqual(sent[0][1][header], value)
                            if follow:
                                self.assertEqual(
                                    sent[-1][1].get(header), value if signed else None
                                )


if __name__ == "__main__":
    unittest.main()
