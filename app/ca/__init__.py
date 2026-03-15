import asyncio

import db
from acme.certificate.service import SerialNumberConverter
from config import settings
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, HTTPException, Response, status
from logger import logger
from pydantic import constr

from . import cronjob
from .service import build_crl_sync, generate_root_ca_sync, load_ca_sync

router = APIRouter(prefix='/ca', tags=['ca'])

if settings.ca.enabled:

    @router.get('/{serial_number}/crl', response_class=Response, responses={200: {'content': {'application/pkix-crl': {}}}})
    async def download_crl(serial_number: constr(pattern='^[0-9A-F]+$')):  # type: ignore[valid-type]
        async with db.transaction(readonly=True) as sql:
            crl_pem = await sql.value("""select crl_pem from cas where serial_number = $1""", serial_number)
        if crl_pem:
            return Response(content=crl_pem, media_type='application/pkix-crl')
        else:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='unknown CA')


    async def init(skip_cronjob: bool = False):
        ca_cert_obj = None
        ca_key_obj = None
        ca_cert_bytes = None
        ca_key_bytes = None

        if (settings.ca.import_dir / 'ca.pem').is_file() and (settings.ca.import_dir / 'ca.key').is_file():
            with open(settings.ca.import_dir / 'ca.key', 'rb') as f:
                ca_key_bytes = f.read()
            with open(settings.ca.import_dir / 'ca.pem', 'rb') as f:
                ca_cert_bytes = f.read()
            ca_key_obj = serialization.load_pem_private_key(ca_key_bytes, None)
            ca_cert_obj = x509.load_pem_x509_certificate(ca_cert_bytes, None)
            logger.info('Importing CA provided in "%s" folder', settings.ca.import_dir)
        else:
            async with db.transaction() as sql:
                active_record = await sql.record("""select cert_pem, key_pem_enc from cas where active=true""")
            
            if active_record:
                ca_cert_obj, ca_key_obj = await asyncio.to_thread(load_ca_sync, cert_pem=active_record[0], key_pem_enc=active_record[1])
            else:
                logger.info('No CA found. Generating a new self-signed Root CA...')
                ca_cert_bytes, ca_key_bytes, ca_cert_obj = await asyncio.to_thread(generate_root_ca_sync)
                ca_key_obj = serialization.load_pem_private_key(ca_key_bytes, None)

        if ca_cert_bytes and ca_key_bytes:
            f = Fernet(settings.ca.encryption_key.get_secret_value())
            ca_key_enc = f.encrypt(ca_key_bytes)
            serial_number = SerialNumberConverter.int2hex(ca_cert_obj.serial_number)

            async with db.transaction(readonly=True) as sql:
                revocations = [record async for record in sql("""select serial_number, revoked_at from certificates where revoked_at is not null""")]
            _, crl_pem = await asyncio.to_thread(build_crl_sync, ca_key=ca_key_obj, ca_cert=ca_cert_obj, revocations=revocations)

            async with db.transaction() as sql:
                await sql.exec("""update cas set active = false""")
                await sql.exec(
                    """
                    insert into cas (serial_number, cert_pem, key_pem_enc, active, crl_pem)
                        values ($1, $2, $3, true, $4)
                    on conflict (serial_number) do update set active = true, crl_pem = $4
                    """,
                    serial_number,
                    ca_cert_bytes.decode(),
                    ca_key_enc,
                    crl_pem,
                )
            logger.info('Successfully initialized CA (Serial: %s)', serial_number)
        
        if not ca_cert_obj or not ca_key_obj:
            raise ValueError('internal ca is enabled but no CA certificate is registered and active.')

        if not skip_cronjob:
            await cronjob.start()
        
        return ca_cert_obj, ca_key_obj
else:

    async def init():
        logger.info('Builtin CA is disabled, relying on custom CA implementation')
