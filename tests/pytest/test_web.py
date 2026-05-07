from unittest import mock

import httpx
import jwcrypto
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from .conftest import TestClient
from .utils import build_csr


def test_get_certificates_page(testclient: TestClient):
    response = testclient.get('/certificates')
    assert response.status_code == 200, response.text
    assert 'Page 1 /' in response.text


def test_get_domains_page(testclient: TestClient):
    response = testclient.get('/domains')
    assert response.status_code == 200, response.text


def test_download_non_existent_cert(testclient: TestClient):
    response = testclient.get('/certificates/DEADBEEF')
    assert response.status_code == 404, response.text


def _issue_http01_certificate(signed_request, directory, domain: str):
    response = signed_request(directory['newAccount'], signed_request.nonce, {'contact': ['mailto:dummy@example.com']})
    account_id = response.headers['Location']

    response = signed_request(directory['newOrder'], response.headers['Replay-Nonce'], {'identifiers': [{'type': 'dns', 'value': domain}]}, account_id)
    authz_url = response.json()['authorizations'][0]
    finalize_order_url = response.json()['finalize']

    response = signed_request(authz_url, response.headers['Replay-Nonce'], '', account_id)
    http_challenge = next(ch for ch in response.json()['challenges'] if ch['type'] == 'http-01')
    challenge_token = http_challenge['token']
    challenge_url = http_challenge['url']

    mock_challenge_file_contents = f'{challenge_token}.{signed_request.account_jwk.thumbprint()}'.rstrip()

    with mock.patch(
        'acme.challenge.service.httpx.AsyncClient.get',
        return_value=httpx.Response(200, text=mock_challenge_file_contents),
    ):
        response = signed_request(challenge_url, response.headers['Replay-Nonce'], '', account_id)
        assert response.status_code == 200

    csr = build_csr([domain])
    response = signed_request(finalize_order_url, response.headers['Replay-Nonce'], {'csr': jwcrypto.common.base64url_encode(csr.public_bytes(Encoding.DER))}, account_id)
    cert_url = response.json()['certificate']

    cert_response = signed_request(cert_url, response.headers['Replay-Nonce'], {}, account_id)
    assert cert_response.status_code == 200
    cert = x509.load_pem_x509_certificate(cert_response.content)
    cert_serial = hex(cert.serial_number)[2:].upper()

    return cert_serial


def test_certificates_page_contains_issued_certificate(signed_request, directory, testclient: TestClient):
    cert_serial = _issue_http01_certificate(signed_request, directory, 'example.com')

    page = testclient.get('/certificates')
    assert page.status_code == 200
    assert cert_serial in page.text
    assert 'example.com' in page.text


def test_certificates_page_pagination(signed_request, directory, testclient: TestClient):
    _issue_http01_certificate(signed_request, directory, 'page1.example.com')
    _issue_http01_certificate(signed_request, directory, 'page2.example.com')

    page1 = testclient.get('/certificates?domainfilter=page&page=1&page_size=1')
    assert page1.status_code == 200
    assert 'Page 1 / 2' in page1.text
    assert 'Next →' in page1.text

    page2 = testclient.get('/certificates?domainfilter=page&page=2&page_size=1')
    assert page2.status_code == 200
    assert 'Page 2 / 2' in page2.text
    assert '← Previous' in page2.text

    page1_has_1 = 'page1.example.com' in page1.text
    page1_has_2 = 'page2.example.com' in page1.text
    page2_has_1 = 'page1.example.com' in page2.text
    page2_has_2 = 'page2.example.com' in page2.text

    assert page1_has_1 != page1_has_2
    assert page2_has_1 != page2_has_2
    assert page1_has_1 != page2_has_1
    assert page1_has_2 != page2_has_2


def test_certificates_page_out_of_range_redirects_to_last_page(signed_request, directory, testclient: TestClient):
    _issue_http01_certificate(signed_request, directory, 'redirect-only.example.com')

    response = testclient.get('/certificates?domainfilter=redirect-only.example.com&page=999&page_size=1', follow_redirects=False)
    assert response.status_code == 302
    assert response.headers['location'].endswith('/certificates?domainfilter=redirect-only.example.com&certstatus=all&page=1&page_size=1')
