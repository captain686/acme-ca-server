import json
import secrets
from typing import Annotated, Literal

from jwcrypto import jwk, jws, common
import db
import mail
from config import settings
from fastapi import APIRouter, Depends, Response, status
from logger import logger
from pydantic import BaseModel, conlist, constr

from ..exceptions import ACMEException
from ..middleware import RequestData, SignedRequest

tosAgreedType = Literal[True] if settings.acme.terms_of_service_url else (bool | None)
contactType = conlist(
    constr(strip_whitespace=True, to_lower=True, pattern=f'^mailto:{settings.acme.mail_target_regex.pattern}$'),
    min_length=1,
    max_length=1,
)
if not settings.acme.mail_required:
    contactType = contactType | conlist(str, min_length=0, max_length=0) | None  # type: ignore[assignment]


class NewOrViewAccountPayload(BaseModel):
    contact: list[str] | None = None
    termsOfServiceAgreed: bool | None = None  # just to view the account no TOS agreement is required
    onlyReturnExisting: bool = False


class NewAccountPayload(BaseModel):
    contact: contactType = []  # type: ignore[valid-type]
    termsOfServiceAgreed: tosAgreedType = None  # type: ignore[valid-type]
    onlyReturnExisting: Literal[False] = False

    @property
    def mail_addr(self) -> str | None:
        return self.contact[0].removeprefix('mailto:') if self.contact else None  # type: ignore[index]


class UpdateAccountPayload(BaseModel):
    status: Literal['deactivated'] | None = None
    contact: contactType | None = None  # type: ignore[valid-type]

    @property
    def mail_addr(self) -> str | None:
        return self.contact[0].removeprefix('mailto:') if self.contact else None


api = APIRouter(tags=['acme:account'])


@api.post('/new-account')
async def create_or_view_account(
    response: Response,
    data: Annotated[RequestData[NewOrViewAccountPayload], Depends(SignedRequest(NewOrViewAccountPayload, allow_new_account=True))],
):
    """
    https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3
    """
    jwk_json: dict = data.key.export(as_dict=True)

    async with db.transaction() as sql:
        result = await sql.record("""select id, mail, status from accounts where jwk=$1 and (id=$2 or $2::text is null)""", jwk_json, data.account_id)
    account_exists = bool(result)

    if account_exists:
        account_id, account_status, mail_addr = result['id'], result['status'], result['mail']
    else:
        if data.payload.onlyReturnExisting:
            raise ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='accountDoesNotExist', detail='Account does not exist', new_nonce=data.new_nonce)
        else:  # create new account
            async with db.transaction() as sql:
                # RFC 8555 Section 7.3.4: External Account Binding
                eab_key_id = None
                if hasattr(data.payload, 'externalAccountBinding') and data.payload.externalAccountBinding:
                     # 1. Parse EAB JWS
                     eab_jws = jws.JWS()
                     eab_jws.deserialize(data.payload.externalAccountBinding)
                     
                     # The "kid" of EAB JWS refers to the server-provided eab_key_id
                     protected = json.loads(common.base64url_decode(eab_jws.objects['protected']).decode())
                     eab_key_id = protected.get('kid')
                     
                     # 2. Fetch EAB key from DB
                     eab_record = await sql.record("select hmac_key from eab_keys where id = $1", eab_key_id)
                     if not eab_record:
                         raise ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='externalAccountRequired', detail='invalid eab key id', new_nonce=data.new_nonce)
                     
                     eab_secret_bytes = eab_record[0]
                     # HMAC key for EAB validation
                     hmac_key = jwk.JWK(kty='oct', k=common.base64url_encode(eab_secret_bytes))
                     
                     # 3. Verify EAB JWS signature
                     try:
                         eab_jws.verify(hmac_key)
                     except Exception:
                         raise ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='externalAccountRequired', detail='eab signature check failed', new_nonce=data.new_nonce)
                     
                     # 4. Canonical payload: it MUST be the same as the public key of the account
                     eab_payload = json.loads(eab_jws.objects['payload'].decode())
                     if eab_payload != jwk_json:
                         raise ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='externalAccountRequired', detail='eab payload mismatch', new_nonce=data.new_nonce)

                # NewAccountPayload contains more checks than NewOrViewAccountPayload
                if settings.acme.external_account_required and not eab_key_id:
                    raise ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='externalAccountRequired', detail='External Account Binding is required', new_nonce=data.new_nonce)

                payload = NewAccountPayload(**data.payload.model_dump())
                mail_addr = payload.mail_addr
                account_id = secrets.token_urlsafe(16)
                
                account_status = await sql.value(
                    """insert into accounts (id, mail, jwk, eab_key_id) values ($1, $2, $3, $4) returning status""",
                    account_id,
                    mail_addr,
                    jwk_json,
                    eab_key_id
                )
            if mail_addr:
                try:
                    await mail.send_new_account_info_mail(mail_addr)
                except Exception:
                    logger.error('could not send new account mail to "%s"', mail_addr, exc_info=True)

    response.status_code = 200 if account_exists else 201
    response.headers['Location'] = f'{str(settings.external_url).rstrip("/")}/acme/accounts/{account_id}'
    return {
        'status': account_status,
        'contact': ['mailto:' + mail_addr] if mail_addr else [],
        'orders': f'{str(settings.external_url).rstrip("/")}/acme/accounts/{account_id}/orders',
    }


@api.post('/key-change')
async def change_key(data: Annotated[RequestData, Depends(SignedRequest())]):
    """
    https://www.rfc-editor.org/rfc/rfc8555#section-7.3.5
    """
    try:
        inner_jws = jws.JWS()
        inner_jws.deserialize(data.raw_payload)
        inner_payload = json.loads(inner_jws.objects['payload'].decode())
        
        # 1. Check account matches
        account_url = f'{str(settings.external_url).rstrip("/")}/acme/accounts/{data.account_id}'
        if inner_payload.get('account') != account_url:
             raise Exception('account URL mismatch')
            
        # 2. Check inner JWS is signed by NEW key
        new_jwk_data = inner_payload.get('newKey')
        if not new_jwk_data:
            raise Exception('missing newKey')
        new_key = jwk.JWK()
        new_key.import_key(**new_jwk_data)
        
        # Verify inner signature with NEW key
        inner_jws.verify(new_key)
        
        # 3. Update account key
        async with db.transaction() as sql:
            await sql.exec(
                """update accounts set jwk = $1 where id = $2 and status = 'valid'""",
                new_key.export(as_dict=True),
                data.account_id
            )
            
        return Response(status_code=status.HTTP_200_OK)
    except Exception as e:
        raise ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='malformed', detail=str(e), new_nonce=data.new_nonce)


@api.post('/accounts/{acc_id}')
async def view_or_update_account(
    acc_id: str,
    data: Annotated[RequestData[UpdateAccountPayload], Depends(SignedRequest(UpdateAccountPayload, allow_blocked_account=True))],
):
    if acc_id != data.account_id:
        raise ACMEException(status_code=status.HTTP_403_FORBIDDEN, exctype='unauthorized', detail='wrong kid', new_nonce=data.new_nonce)

    if 'contact' in data.payload.model_fields_set:  # contact has been set explicitly and is not the default `None` from model definition
        async with db.transaction() as sql:
            result = await sql.exec("""update accounts set mail=$1 where id = $2 and status = 'valid'""", data.payload.mail_addr, acc_id)
        account_is_valid = result == 'UPDATE 1'
        if data.payload.mail_addr and account_is_valid:
            try:
                await mail.send_new_account_info_mail(data.payload.mail_addr)
            except Exception:
                logger.error('could not send new account mail to "%s"', data.payload.mail_addr, exc_info=True)

    if data.payload.status == 'deactivated':  # https://www.rfc-editor.org/rfc/rfc8555#section-7.3.6
        async with db.transaction() as sql:
            await sql.exec("""update accounts set status='deactivated' where id = $1""", acc_id)
            await sql.exec(
                """
                update orders set status='invalid', error=row('unauthorized','account deactivated')
                where account_id = $1 and status <> 'invalid'
                """,
                acc_id,
            )

    async with db.transaction(readonly=True) as sql:
        account_status, mail_addr = await sql.record("""select status, mail from accounts where id = $1""", acc_id)

    return {
        'status': account_status,
        'contact': ['mailto:' + mail_addr] if mail_addr else [],
        'orders': f'{str(settings.external_url).rstrip("/")}/acme/accounts/{acc_id}/orders',
    }


@api.post('/accounts/{acc_id}/orders', tags=['acme:order'])
async def view_orders(acc_id: str, data: Annotated[RequestData, Depends(SignedRequest())]):
    if acc_id != data.account_id:
        raise ACMEException(status_code=status.HTTP_403_FORBIDDEN, exctype='unauthorized', detail='wrong account id provided', new_nonce=data.new_nonce)
    async with db.transaction(readonly=True) as sql:
        orders = [order_id async for order_id, *_ in sql("""select id from orders where account_id = $1 and status <> 'invalid'""", acc_id)]
    return {
        'orders': [f'{str(settings.external_url).rstrip("/")}/acme/orders/{order_id}' for order_id in orders],
    }
