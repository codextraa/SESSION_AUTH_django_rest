#!/bin/sh
export INFISICAL_TOKEN=$(cat /run/secrets/infisical_token)
cd /run/secrets
infisical run --path="/Session-django-rest/backend" -- sh -c '
  { if [ "$DJANGO_ENV" = "production" ]; then cd /home/django/app; else cd /app; fi; } &&

  export PYTHONUNBUFFERED="${PYTHONUNBUFFERED:-1}"

  echo "Loading GCP service account credentials..."
  printf "%s" "$GCP_SERVICE_ACCOUNT_JSON" > /tmp/gcp-service-account.json
  chmod 600 /tmp/gcp-service-account.json
  export GOOGLE_APPLICATION_CREDENTIALS="/tmp/gcp-service-account.json"
  
  if [ "$SERVICE_TYPE" = "server-api" ]; then
    echo "Running in SERVER-API mode..."

    if [ "$DJANGO_ENV" = "production" ]; then
      echo "Running in PRODUCTION mode..."
      echo "Testing network reachability to remote PostgreSQL server at $DB_HOST:$DB_PORT..."
      
      retries=5
      delay=3
      attempt=1
      while [ $attempt -le $retries ]; do
        python -c "
import sys, psycopg2
try:
    psycopg2.connect(
        dbname=\"$DB_NAME\", 
        user=\"$DB_USER\", 
        password=\"$DB_PASSWORD\", 
        host=\"$DB_HOST\", 
        port=\"$DB_PORT\", 
        connect_timeout=3
    )
except Exception as e:
    sys.stderr.write(f\"Database connection failed: {e}\n\")
    sys.exit(1)
"

        if [ $? -eq 0 ]; then
          echo "✅ Remote PostgreSQL database '\''$DB_NAME'\'' is reachable and ready!"
          break
        fi

        echo "Attempt $attempt/$retries: Waiting for remote PostgreSQL database..."
        sleep $delay
        attempt=$((attempt + 1))
        
        if [ $attempt -gt $retries ]; then
          echo "❌ Error: Remote PostgreSQL database not available after $retries attempts. Exiting..." >&2
          exit 1
        fi
      done
    else
      # Test PostgreSQL connection with retry and fallback
      echo "Running in DEVELOPMENT mode..."
      echo "Testing connection to PostgreSQL server at $DB_HOST:$DB_PORT..."
      retries=5
      delay=2
      attempt=1
      while [ $attempt -le $retries ]; do
        if pg_isready -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER"; then
          echo "✅ PostgreSQL server is ready!"
          break
        fi
        echo "Attempt $attempt/$retries: Waiting for PostgreSQL server to be ready..."
        sleep $delay
        attempt=$((attempt + 1))
        if [ $attempt -gt $retries ]; then
          echo "❌ Error: PostgreSQL server not available after $retries attempts. Exiting..." >&2
          exit 1
        fi
      done

      # Check if database exists, create it if not
      echo "Checking if database '\''$DB_NAME'\'' exists..."
      if PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -c "SELECT 1 FROM pg_database WHERE datname='\''$DB_NAME'\''" | grep -q 1; then
        echo "✅ Database '\''$DB_NAME'\'' already exists."
      else
        echo "Database '\''$DB_NAME'\'' does not exist. Creating it..."
        if PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -c "CREATE DATABASE $DB_NAME"; then
          echo "✅ Database '\''$DB_NAME'\'' created successfully!"
        else
          echo "❌ Error: Failed to create database '\''$DB_NAME'\''. Exiting..." >&2
          exit 1
        fi
      fi
    fi

    if [ "$DJANGO_ENV" = "production" ]; then
      # Migrate to db for production
      echo "Migrating to database..."
      python manage.py migrate --noinput

      # Compile static assets for production
      echo "Collecting static files..."
      python manage.py collectstatic --noinput

      # Start Gunicorn server in production mode
      echo "Starting Gunicorn production server..."
      gunicorn server.wsgi:application \
        --bind 0.0.0.0:8000 \
        --workers=4 \
        --threads=2 \
        --timeout=120 \
        --access-logfile - \
        --error-logfile -
    else
      # Migrate to db for development
      echo "Migrating to database..."
      python manage.py migrate

      # Start Django development server
      echo "Starting Django development server..."
      python manage.py runserver 0.0.0.0:8000
    fi
  else
    # Start Workers
    echo "Waiting for SERVER-API to finish migrations..."
    retries=10
    delay=3
    attempt=1

    while [ $attempt -le $retries ]; do
      # python manage.py migrate --check returns 0 if all migrations are applied
      python manage.py migrate --check
      
      if [ $? -eq 0 ]; then
        echo "✅ Migrations complete. Worker starting..."
        break
      fi

      echo "Attempt $attempt/$retries: Migrations pending. Sleeping ${delay}s..."
      sleep $delay
      attempt=$((attempt + 1))
      [ $attempt -gt $retries ] && echo "❌ Error: SERVER-API migrations timed out. Worker exiting..." && exit 1
    done

    if [ "$DJANGO_ENV" = "production" ]; then
      echo "Starting Production Celery Workers (Thread Pool, Concurrency: ${CELERY_WORKER_CONCURRENCY:-4})..."
      celery -A server worker \
             --loglevel=info \
             --pool=gevent \
             --concurrency=${CELERY_WORKER_CONCURRENCY:-4}
    else
      echo "Starting Development Celery Workers (Prefork, Concurrency: ${CELERY_WORKER_CONCURRENCY:-4})..."
      celery -A server worker --loglevel=info --concurrency=${CELERY_WORKER_CONCURRENCY:-4}
    fi
  fi
'