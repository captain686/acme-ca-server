import math
from pathlib import Path
from typing import Literal

import db
from config import settings
from fastapi import APIRouter, HTTPException, Query, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from jinja2 import Environment, FileSystemLoader
from pydantic import constr

template_engine = Environment(loader=FileSystemLoader(Path(__file__).parent / 'templates'), enable_async=True, autoescape=True)

async def get_default_params():
    app_title = settings.web.app_title
    if app_title == 'ACME CA Server' and settings.ca.root_ca_common_name != 'ACME Root CA':
        app_title = settings.ca.root_ca_common_name
        
    return {
        'app_title': app_title,
        'app_desc': settings.web.app_description,
        'web_url': str(settings.external_url),
        'acme_url': str(settings.external_url).removesuffix('/') + '/acme/directory',
        'ca_name': settings.ca.root_ca_common_name,
        'ca_org': settings.ca.root_ca_organization,
    }


api = APIRouter(tags=['web'])


@api.get('/', response_class=HTMLResponse)
async def index():
    params = await get_default_params()
    return await template_engine.get_template('index.html').render_async(**params)


if settings.web.enable_public_log:

    @api.get('/certificates', response_class=HTMLResponse)
    async def certificate_log(
        domainfilter: str = '',
        certstatus: Literal['all', 'valid', 'invalid'] = 'all',
        page: int = Query(1, ge=1),
        page_size: int = Query(100, ge=1, le=500),
    ):
        offset = (page - 1) * page_size
        filter_text = domainfilter.replace('*', '%')

        async with db.transaction(readonly=True) as sql:
            total_count = await sql.value(
                """
                with data as (
                    select
                        cert.serial_number,
                        cert.not_valid_before,
                        cert.not_valid_after,
                        cert.revoked_at,
                        (cert.not_valid_after > now() and cert.revoked_at is null) as is_valid,
                        (cert.not_valid_after - cert.not_valid_before) as lifetime,
                        (now() - cert.not_valid_before) as age,
                        coalesce(array_agg(distinct authz.domain order by authz.domain) filter (where authz.domain is not null), '{}'::text[]) as domains
                    from certificates cert
                    left join authorizations authz on authz.order_id = cert.order_id
                    where ($1::text = '' or authz.domain ilike '%' || $1::text || '%')
                    group by cert.serial_number, cert.not_valid_before, cert.not_valid_after, cert.revoked_at
                )
                select count(*) from data
                where ($2 = 'all' or ($2 = 'valid' and is_valid) or ($2 = 'invalid' and not is_valid))
                """,
                filter_text,
                certstatus,
            )

            certs = [
                record
                async for record in sql(
                    """
                    with data as (
                        select
                            cert.serial_number,
                            cert.not_valid_before,
                            cert.not_valid_after,
                            cert.revoked_at,
                            (cert.not_valid_after > now() and cert.revoked_at is null) as is_valid,
                            (cert.not_valid_after - cert.not_valid_before) as lifetime,
                            (now() - cert.not_valid_before) as age,
                            coalesce(array_agg(distinct authz.domain order by authz.domain) filter (where authz.domain is not null), '{}'::text[]) as domains
                        from certificates cert
                        left join authorizations authz on authz.order_id = cert.order_id
                        where ($1::text = '' or authz.domain ilike '%' || $1::text || '%')
                        group by cert.serial_number, cert.not_valid_before, cert.not_valid_after, cert.revoked_at
                    )
                    select * from data
                    where ($2 = 'all' or ($2 = 'valid' and is_valid) or ($2 = 'invalid' and not is_valid))
                    order by not_valid_after desc
                    limit $3 offset $4
                    """,
                    filter_text,
                    certstatus,
                    page_size,
                    offset,
                )
            ]

        total_count = int(total_count or 0)
        total_pages = max(1, math.ceil(total_count / page_size))
        if page > total_pages:
            from urllib.parse import urlencode

            query = urlencode(
                {
                    'domainfilter': domainfilter,
                    'certstatus': certstatus,
                    'page': total_pages,
                    'page_size': page_size,
                }
            )
            return RedirectResponse(url=f'/certificates?{query}', status_code=status.HTTP_302_FOUND)

        params = await get_default_params()
        return await template_engine.get_template('cert-log.html').render_async(
            **params,
            certs=certs,
            certstatus=certstatus,
            domainfilter=domainfilter,
            page=page,
            page_size=page_size,
            total_count=total_count,
            total_pages=total_pages,
            has_prev=page > 1,
            has_next=page < total_pages,
            prev_page=max(1, page - 1),
            next_page=min(total_pages, page + 1),
        )

    @api.get('/certificates/{serial_number}', response_class=Response, responses={200: {'content': {'application/pem-certificate-chain': {}}}})
    async def download_certificate(serial_number: constr(pattern='^[0-9A-F]+$')):  # type: ignore[valid-type]
        async with db.transaction(readonly=True) as sql:
            pem_chain = await sql.value("""select chain_pem from certificates where serial_number = $1""", serial_number)
        if not pem_chain:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='unknown certificate')
        return Response(content=pem_chain, media_type='application/pem-certificate-chain')

    @api.get('/domains', response_class=HTMLResponse)
    async def domain_log(domainfilter: str = '', domainstatus: Literal['all', 'valid', 'invalid'] = 'all'):
        async with db.transaction(readonly=True) as sql:
            domains = [
                record
                async for record in sql(
                    """
                    with data as (
                        select
                            authz.domain as domain_name,
                            min(cert.not_valid_before) as first_requested_at,
                            max(cert.not_valid_after) as expires_at,
                            (max(cert.not_valid_after) FILTER (WHERE revoked_at is null)) > now() AS is_valid
                        from orders ord
                        join authorizations authz on authz.order_id = ord.id
                        join certificates cert on cert.order_id = ord.id
                        where ($1::text = '' or authz.domain ilike '%' || $1::text || '%')
                        group by authz.domain
                    )
                    select * from data
                    where ($2 = 'all' or ($2 = 'valid' and is_valid) or ($2 = 'invalid' and not is_valid))
                    order by domain_name
                    """,
                    domainfilter.replace('*', '%'),
                    domainstatus,
                )
            ]
        params = await get_default_params()
        return await template_engine.get_template('domain-log.html').render_async(**params, domains=domains, domainstatus=domainstatus, domainfilter=domainfilter)
else:

    @api.get('/certificates')
    async def certificate_log_disabled():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='This page is disabled')

    @api.get('/domains')
    async def domain_log_disabled():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='This page is disabled')
