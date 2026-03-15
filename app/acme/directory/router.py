from config import settings
from fastapi import APIRouter

api = APIRouter(tags=['acme:directory'])


@api.get('/directory')
async def get_directory():
    """
    See RFC 8555 7.1.1 "Directory" <https://www.rfc-editor.org/rfc/rfc8555#section-7.1.1>
    """

    meta = {'website': str(settings.external_url), 'externalAccountRequired': settings.acme.external_account_required}
    if settings.acme.terms_of_service_url:
        meta['termsOfService'] = str(settings.acme.terms_of_service_url)
    
    base = str(settings.external_url).rstrip('/')
    return {
        'newNonce': f'{base}/acme/new-nonce',
        'newAccount': f'{base}/acme/new-account',
        'newOrder': f'{base}/acme/new-order',
        'revokeCert': f'{base}/acme/revoke-cert',
        'keyChange': f'{base}/acme/key-change',
        'renewalInfo': f'{base}/acme/renewal-info/',
        # newAuthz: is not supported
        'meta': meta,
    }
