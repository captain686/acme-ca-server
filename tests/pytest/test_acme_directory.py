from .conftest import TestClient


def test_show_directory(testclient: TestClient):
    response = testclient.get('/acme/directory')
    assert response.status_code == 200
    assert response.headers['Content-Type'] == 'application/json'

    payload = response.json()
    assert payload['newNonce'] == 'http://localhost:8000/acme/new-nonce'
    assert payload['newAccount'] == 'http://localhost:8000/acme/new-account'
    assert payload['newOrder'] == 'http://localhost:8000/acme/new-order'
    assert payload['revokeCert'] == 'http://localhost:8000/acme/revoke-cert'
    assert payload['keyChange'] == 'http://localhost:8000/acme/key-change'
    assert payload['renewalInfo'] == 'http://localhost:8000/acme/renewal-info/'
    assert payload['meta']['website'] == 'http://localhost:8000/'
    assert payload['meta']['externalAccountRequired'] is False


def test_directory_shows_terms(testclient: TestClient, monkeypatch):
    import config

    monkeypatch.setattr(config.settings.acme, 'terms_of_service_url', 'https://example.com/terms.html')
    response = testclient.get('/acme/directory')
    assert response.status_code == 200

    payload = response.json()
    assert payload['newNonce'] == 'http://localhost:8000/acme/new-nonce'
    assert payload['newAccount'] == 'http://localhost:8000/acme/new-account'
    assert payload['newOrder'] == 'http://localhost:8000/acme/new-order'
    assert payload['revokeCert'] == 'http://localhost:8000/acme/revoke-cert'
    assert payload['keyChange'] == 'http://localhost:8000/acme/key-change'
    assert payload['renewalInfo'] == 'http://localhost:8000/acme/renewal-info/'
    assert payload['meta']['website'] == 'http://localhost:8000/'
    assert payload['meta']['termsOfService'] == 'https://example.com/terms.html'
    assert payload['meta']['externalAccountRequired'] is False
