import asyncio
import hashlib
import httpx
import jwcrypto.common
import jwcrypto.jwk
import jwcrypto.jws
from typing import Literal
from fastapi import status

from config import settings
from ..exceptions import ACMEException


import dns.resolver
import dns.exception

async def check_challenge_is_fulfilled(*, domain: str, token: str, jwk: jwcrypto.jwk.JWK, type: Literal['http-01', 'dns-01'], new_nonce: str | None = None):
    for _ in range(3):  # 3x retry
        err: Literal[False] | ACMEException
        try:
            if type == 'http-01':
                async with httpx.AsyncClient(
                    timeout=10,
                    verify=False,  # noqa: S501
                    http1=True,
                    http2=False,
                    follow_redirects=True,
                    trust_env=False,
                ) as client:
                    res = await client.get(f'http://{domain}:80/.well-known/acme-challenge/{token}')
                    if res.status_code == 200 and res.text.rstrip() == f'{token}.{jwk.thumbprint()}':
                        err = False
                    else:
                        err = ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='incorrectResponse', detail='presented token does not match challenge', new_nonce=new_nonce)
            elif type == 'dns-01':
                # For wildcards, the domain is already the parent domain (e.g. example.com for *.example.com)
                validation_domain = f'_acme-challenge.{domain}'
                expected_value = jwcrypto.jws.JWS()._encode_content(jwk.thumbprint().encode()) # Wait, thumbprint needs to be hashed?
                # RFC 8555: base64(sha256(token || "." || thumbprint))
                key_auth = f'{token}.{jwk.thumbprint()}'.encode()
                expected_txt = jwcrypto.common.base64url_encode(hashlib.sha256(key_auth).digest())
                
                try:
                    resolver = dns.resolver.Resolver()
                    if settings.acme.dns_servers:
                        resolver.nameservers = settings.acme.dns_servers
                    
                    answers = await asyncio.to_thread(resolver.resolve, validation_domain, 'TXT')
                    found = False
                    for rdata in answers:
                        for txt_record in rdata.strings:
                            if txt_record.decode() == expected_txt:
                                found = True
                                break
                    if found:
                        err = False
                    else:
                        err = ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='incorrectResponse', detail='TXT record not found or does not match', new_nonce=new_nonce)
                except dns.resolver.NXDOMAIN:
                    err = ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='dns', detail='domain does not exist', new_nonce=new_nonce)
                except dns.resolver.NoAnswer:
                    err = ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='dns', detail='no TXT record found', new_nonce=new_nonce)
                except dns.exception.DNSException as e:
                    err = ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='dns', detail=f'DNS error: {str(e)}', new_nonce=new_nonce)
        except httpx.ConnectTimeout:
            err = ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='connection', detail='timeout', new_nonce=new_nonce)
        except httpx.ConnectError:
            err = ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='dns', detail='could not resolve address', new_nonce=new_nonce)
        except Exception as e:
            err = ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='serverInternal', detail=f'could not validate challenge: {str(e)}', new_nonce=new_nonce)
        
        if err is False:
            return
        await asyncio.sleep(3)
    raise err
