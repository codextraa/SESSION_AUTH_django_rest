#!/bin/sh
export INFISICAL_TOKEN=$(cat /run/secrets/infisical_token)
cd /run/secrets
infisical run --path="/Session-django-rest/frontend" -- sh -c '
    cd /app
    
    # Handle local CA certificate if provided
    if [ -n "$local_ca" ]; then
        echo "$local_ca" > /tmp/local-ca.pem
        export NODE_EXTRA_CA_CERTS=/tmp/local-ca.pem
    fi
    
    # Check environment and start appropriate server
    if [ "$NODE_ENV" = "production" ]; then
        echo "Starting Next.js in production mode..."
        npm start
    else
        echo "Starting Next.js in development mode..."
        npm run dev
    fi
'