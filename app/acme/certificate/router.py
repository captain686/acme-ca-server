import json
from typing import Annotated

import db
from ca import service as ca_service
from fastapi import APIRouter, Depends, Header, Response, status
from jwcrypto.common import base64url_decode
import jwcrypto.jwk
import jwcrypto.jws
from pydantic import BaseModel, constr
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ..exceptions import ACMEException
from ..middleware import RequestData, SignedRequest
from .service import SerialNumberConverter, parse_cert


class RevokeCertPayload(BaseModel):
    certificate: constr(min_length=1, max_length=1 * 1024**2)  # type: ignore[valid-type]
    reason: int | None = None  # not evaluated


api = APIRouter(tags=['acme:certificate'])


@api.post('/certificates/{serial_number}', response_class=Response, responses={200: {'content': {'application/pem-certificate-chain': {}}}})
async def download_cert(
    response: Response,
    serial_number: constr(pattern='^[0-9A-F]+$'),  # type: ignore[valid-type]
    data: Annotated[RequestData, Depends(SignedRequest())],
    accept: str = Header(
        default='*/*', pattern=r'(application/pem\-certificate\-chain|\*/\*)', description='Certificates are only supported as "application/pem-certificate-chain"'
    ),
):
    async with db.transaction(readonly=True) as sql:
        pem_chain = await sql.value(
            """
            select cert.chain_pem from certificates cert
            join orders ord on cert.order_id = ord.id
            where cert.serial_number = $1 and ord.account_id = $2
            """,
            serial_number,
            data.account_id,
        )
    if not pem_chain:
        raise ACMEException(status_code=status.HTTP_404_NOT_FOUND, exctype='malformed', detail='specified certificate not found for current account', new_nonce=data.new_nonce)
    return Response(content=pem_chain, headers=response.headers, media_type='application/pem-certificate-chain')


@api.post('/revoke-cert', response_class=Response)
async def revoke_cert(data: Annotated[RequestData[RevokeCertPayload], Depends(SignedRequest(RevokeCertPayload, allow_new_account=True))]):
    """
    https://www.rfc-editor.org/rfc/rfc8555#section-7.6
    """
    # this request might use account id or the account public key
    jwk_json: dict = data.key.export(as_dict=True)
    cert_bytes = base64url_decode(data.payload.certificate)
    cert = await parse_cert(cert_bytes)
    serial_number = SerialNumberConverter.int2hex(cert.serial_number)
    
    # RFC 8555 Section 7.6:
    # "The server MUST consider the revocation request valid if it is signed by..."
    # 1. Account that requested the certificate
    # 2. Account that owns the identifiers
    # 3. Private key corresponding to the public key in the certificate
    
    async with db.transaction(readonly=True) as sql:
        # Check if authorized by account OR if the JWS key matches the cert key
        # We also check if the certificate exists and is not already revoked.
        record = await sql.record(
            """
            select c.order_id, a.id as acc_id, c.revoked_at, a.jwk as acc_jwk
            from certificates c
            left join orders o on o.id = c.order_id
            left join accounts a on a.id = o.account_id
            where c.serial_number = $1
            """,
            serial_number
        )
        
    if not record:
        raise ACMEException(status_code=status.HTTP_404_NOT_FOUND, exctype='malformed', detail='certificate not found', new_nonce=data.new_nonce)
    
    order_id, account_id, already_revoked, acc_jwk = record
    if already_revoked:
         raise ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='alreadyRevoked', detail='certificate already revoked', new_nonce=data.new_nonce)

    is_authorized = False
    
    # Auth Case 1: Signed by the account that requested the cert
    if data.account_id and data.account_id == account_id:
        is_authorized = True
    
    # Auth Case 2: Signed by the certificate key
    # (data.account_id will be None if middleware used JWK instead of KID)
    # Check if the JWS key thumbprint matches the cert key thumbprint
    import hashlib
    def get_thumbprint(jwk_dict):
        # Simplification: use thumbprint of JWK
        temp_key = jwcrypto.jwk.JWK()
        temp_key.import_key(**jwk_dict)
        return temp_key.thumbprint()

    # Extract public key from cert using cryptography
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    
    cert_obj = x509.load_der_x509_certificate(cert_bytes)
    cert_pub_key = cert_obj.public_key()
    # Convert cert pub key to JWK for comparison
    # (Or just compare exported PEM/DER)
    # Actually, simpler: middleware already loaded the JWS key into data.key.
    # We just need to check if data.key matches the cert_pub_key.
    
    # For now, let's just check if it was signed by the account that owns it
    # OR if it was signed by a JWK (new_account=True in middleware allows this)
    if not is_authorized and not data.account_id:
        # Check if data.key matches cert_pub_key
        # export both to PEM and compare
        jws_pub_pem = data.key.export_to_pem()
        cert_pub_pem = cert_pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        if jws_pub_pem.strip() == cert_pub_pem.strip():
            is_authorized = True

    if not is_authorized:
        raise ACMEException(status_code=status.HTTP_403_FORBIDDEN, exctype='unauthorized', detail='not authorized to revoke this certificate', new_nonce=data.new_nonce)

    async with db.transaction(readonly=True) as sql:
        revocation_list = [(sn, rev_at) async for sn, rev_at in sql("""select serial_number, revoked_at from certificates where revoked_at is not null""")]
        revoked_at = await sql.value("""select now()""")
    
    revocations = set(revocation_list)
    revocations.add((serial_number, revoked_at))
    
    # RFC 5280 Reason codes
    reason = data.payload.reason if data.payload.reason is not None else 0
    
    await ca_service.revoke_cert(serial_number=serial_number, revocations=revocations)
    
    async with db.transaction() as sql:
        await sql.exec(
            """update certificates set revoked_at = $2, revocation_reason = $3 where serial_number = $1 and revoked_at is null""",
            serial_number,
            revoked_at,
            reason
        )
