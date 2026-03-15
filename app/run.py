import uvicorn
import asyncio
from urllib.parse import urlparse
from pathlib import Path

import db
import db.migrations
import ca
from ca.service import generate_server_cert_sync
from main import app
from config import settings
from logger import logger
from ca.service import generate_server_cert_sync

async def setup():
    logger.info("Starting pre-flight setup...")
    await db.connect()
    await db.migrations.run()
    
    if settings.ca.enabled:
        ca_cert, ca_key = await ca.init(skip_cronjob=True)
        
        # Determine if we should use SSL
        url = str(settings.external_url)
        is_https = url.startswith("https://")
        
        cert_path = settings.web.ssl_cert_file
        key_path = settings.web.ssl_key_file

        # Auto-issue if requested and path not provided or not exists
        if is_https and settings.ca.auto_issue_server_cert:
            if not cert_path or not key_path:
                cert_path = Path("cert.pem")
                key_path = Path("key.pem")
                # Update settings in memory so run.py sees them
                settings.web.ssl_cert_file = cert_path
                settings.web.ssl_key_file = key_path
            
            if not cert_path.exists() or not key_path.exists():
                hostname = urlparse(url).hostname or "localhost"
                logger.info("Auto-issuing server certificate for host: %s", hostname)
                
                cert_pem, key_pem = await asyncio.to_thread(generate_server_cert_sync, ca_key=ca_key, ca_cert=ca_cert, hostname=hostname)
                
                cert_path.parent.mkdir(parents=True, exist_ok=True)
                cert_path.write_bytes(cert_pem)
                key_path.write_bytes(key_pem)
                logger.info("Server certificate issued and saved to %s", cert_path)

    await db.disconnect()
    logger.info("Pre-flight setup complete.")

if __name__ == "__main__":
    asyncio.run(setup())
    
    parsed_url = urlparse(str(settings.external_url))
    ext_port = parsed_url.port
    
    config = {
        "app": app, # Use object directly to avoid re-importing issues
        "host": "0.0.0.0",
        "port": 8080,
        "server_header": False
    }

    cert_path = settings.web.ssl_cert_file
    key_path = settings.web.ssl_key_file

    if cert_path and key_path and cert_path.exists() and key_path.exists():
        config["port"] = ext_port or 8443
        config["ssl_certfile"] = str(cert_path)
        config["ssl_keyfile"] = str(key_path)
        logger.info("Starting in HTTPS mode on port %s", config["port"])
    else:
        config["port"] = ext_port or 8080
        if cert_path or key_path:
            logger.warning("SSL files configured but not found or incomplete. Falling back to HTTP.")
        else:
            logger.info("Starting in HTTP mode on port %s", config["port"])

    uvicorn.run(**config)
