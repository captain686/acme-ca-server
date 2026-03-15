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
    # Initialize DB and CA first to see if we need to auto-generate certs
    await db.connect()
    await db.migrations.run()
    ca_cert, ca_key = await ca.init(skip_cronjob=True)

    # Enable HTTPS if certificate and key are provided
    if settings.ssl_cert_file and settings.ssl_key_file:
        cert_path = settings.ssl_cert_file
        key_path = settings.ssl_key_file
        
        if not cert_path.exists() or not key_path.exists():
            if settings.ca.enabled and settings.ca.auto_issue_server_cert:
                from urllib.parse import urlparse
                hostname = urlparse(str(settings.external_url)).hostname or "localhost"
                
                logger.info("SSL certificate files not found. Auto-issuing for %s...", hostname)
                cert_pem, key_pem = await asyncio.to_thread(generate_server_cert_sync, ca_key=ca_key, ca_cert=ca_cert, hostname=hostname)
                
                cert_path.parent.mkdir(parents=True, exist_ok=True)
                cert_path.write_bytes(cert_pem)
                key_path.write_bytes(key_pem)
                logger.info("Successfully issued and saved server certificate to %s", cert_path)
    
    await db.disconnect()

if __name__ == "__main__":
    # Run pre-flight setup
    asyncio.run(setup())
    
    parsed_url = urlparse(str(settings.external_url))
    ext_port = parsed_url.port
    
    config = {
        "app": "main:app",
        "host": "0.0.0.0",
        "port": 8080,
        "server_header": False
    }

    if settings.ssl_cert_file and settings.ssl_key_file:
        if settings.ssl_cert_file.exists() and settings.ssl_key_file.exists():
            config["port"] = ext_port or 8443
            config["ssl_certfile"] = str(settings.ssl_cert_file)
            config["ssl_keyfile"] = str(settings.ssl_key_file)
            logger.info("Starting HTTPS server on port %s using %s", config["port"], settings.ssl_cert_file)
        else:
            config["port"] = ext_port or 8080
            logger.warning("SSL files not found, starting in HTTP mode on port %d", config["port"])
    else:
        config["port"] = ext_port or 8080
        logger.info("Starting HTTP server on port %d", config["port"])

    uvicorn.run(**config)
