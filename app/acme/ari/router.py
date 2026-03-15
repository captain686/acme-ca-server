from typing import Annotated
from fastapi import APIRouter, Depends, Response, status
from logger import logger
from pydantic import BaseModel
from ..middleware import RequestData, SignedRequest
from ..exceptions import ACMEException
from config import settings
import db
import jwcrypto.jwk

api = APIRouter(tags=['acme:ari'])

@api.get('/renewal-info/{serial_number}')
async def get_renewal_info(serial_number: str):
    """
    ACME Renewal Information (ARI)
    https://www.rfc-editor.org/rfc/rfc9460.html
    """
    async with db.transaction(readonly=True) as sql:
        record = await sql.record(
            "select not_valid_after from certificates where serial_number = $1",
            serial_number
        )
    
    if not record:
        raise ACMEException(status_code=status.HTTP_404_NOT_FOUND, exctype='malformed', detail='certificate not found')
    
    expiry = record[0]
    # Standard recommendation: suggest renewal between 30 and 10 days before expiry
    # or simple heuristic: start = expiry - 30 days, end = expiry - 7 days
    from datetime import timedelta
    start = expiry - timedelta(days=30)
    end = expiry - timedelta(days=7)
    
    # If already past renewal or very close, adjust
    now = await db.transaction(readonly=True).value("select now()") # use DB time for consistency
    if start < now:
        start = now + timedelta(hours=1)
        if end < start:
            end = start + timedelta(days=1)

    return {
        "suggestedWindow": {
            "start": start.isoformat() + 'Z',
            "end": end.isoformat() + 'Z'
        }
    }
