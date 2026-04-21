import hashlib
from unittest import mock

import jwcrypto

# Utilities

def _expected_dns_txt(token: str, thumbprint: str) -> str:
    # RFC 8555: base64url(sha256(token || "." || thumbprint))
    key_auth = f"{token}.{thumbprint}".encode()
    return jwcrypto.common.base64url_encode(hashlib.sha256(key_auth).digest())


def test_wildcard_order_has_only_dns01(signed_request, directory):
    # Create account
    resp = signed_request(directory['newAccount'], signed_request.nonce, {'contact': ['mailto:test@example.com']})
    account_url = resp.headers['Location']

    # Create order with wildcard identifier
    resp = signed_request(
        directory['newOrder'],
        resp.headers['Replay-Nonce'],
        {'identifiers': [{'type': 'dns', 'value': '*.example.org'}]},
        account_url,
    )

    # Retrieve authorization and verify only dns-01 is present
    authz_url = resp.json()['authorizations'][0]
    resp = signed_request(authz_url, resp.headers['Replay-Nonce'], '', account_url)
    challenges = resp.json()['challenges']
    types = sorted(ch['type'] for ch in challenges)
    assert types == ['dns-01']

    # Prepare DNS mock for verification
    dns_chal = challenges[0]
    token = dns_chal['token']
    expected_txt = _expected_dns_txt(token, signed_request.account_jwk.thumbprint())

    class _Rdata:
        def __init__(self, s: str):
            # dnspython rdata.strings is a list[bytes]
            self.strings = [s.encode()]

    class _Answers(list):
        pass

    class _Resolver:
        def resolve(self, name, rdtype):
            return _Answers([_Rdata(expected_txt)])

    with mock.patch('dns.resolver.Resolver', return_value=_Resolver()):
        # Trigger verification on the challenge URL
        verify_resp = signed_request(dns_chal['url'], resp.headers['Replay-Nonce'], '', account_url)
        assert verify_resp.status_code == 200, verify_resp.text
        assert verify_resp.json()['status'] == 'valid', verify_resp.json()


def test_non_wildcard_has_both_dns01_and_http01(signed_request, directory):
    # Create account
    resp = signed_request(directory['newAccount'], signed_request.nonce, {'contact': ['mailto:test@example.com']})
    account_url = resp.headers['Location']

    # Create order with normal identifier
    resp = signed_request(
        directory['newOrder'],
        resp.headers['Replay-Nonce'],
        {'identifiers': [{'type': 'dns', 'value': 'example.com'}]},
        account_url,
    )

    # Retrieve authorization and verify both challenge types exist
    authz_url = resp.json()['authorizations'][0]
    resp = signed_request(authz_url, resp.headers['Replay-Nonce'], '', account_url)
    challenges = resp.json()['challenges']
    types = sorted(set(ch['type'] for ch in challenges))
    assert types == ['dns-01', 'http-01']

    # We won't fully verify here (covered by http-01 and wildcard dns test)
