#!/bin/sh
export INFISICAL_TOKEN=$(cat /run/secrets/infisical_token)
cd /run/secrets
infisical run --path="/Session-django-rest/backend" -- sh -c '
  cd /app &&
  
  # Test PostgreSQL connection with retry and fallback
  echo "Testing connection to PostgreSQL server at $DB_HOST:$DB_PORT..."
  retries=5
  delay=2
  attempt=1
  while [ $attempt -le $retries ]; do
    if pg_isready -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER"; then
      echo "PostgreSQL server is ready!"
      break
    fi
    echo "Attempt $attempt/$retries: Waiting for PostgreSQL server to be ready..."
    sleep $delay
    attempt=$((attempt + 1))
    if [ $attempt -gt $retries ]; then
      echo "Error: PostgreSQL server not available after $retries attempts. Exiting..." >&2
      exit 1
    fi
  done

  # Check if database exists, create it if not
  echo "Checking if database '\''$DB_NAME'\'' exists..."
  if PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -c "SELECT 1 FROM pg_database WHERE datname='\''$DB_NAME'\''" | grep -q 1; then
    echo "Database '\''$DB_NAME'\'' already exists."
  else
    echo "Database '\''$DB_NAME'\'' does not exist. Creating it..."
    if PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -c "CREATE DATABASE $DB_NAME"; then
      echo "Database '\''$DB_NAME'\'' created successfully!"
    else
      echo "Error: Failed to create database '\''$DB_NAME'\''. Exiting..." >&2
      exit 1
    fi
  fi

  # Migrate to db
  echo "Migrating to database..."
  python manage.py migrate

  # Check environment and start appropriate server
  if [ "$DJANGO_ENV" = "production" ]; then
    # Start Gunicorn in production mode
    echo "Starting Gunicorn production server..."
    gunicorn backend.wsgi:application --bind 0.0.0.0:8000 --workers=4 --threads=2 --timeout=120
  else
    # Start Django development server
    echo "Starting Django development server..."
    python manage.py runserver 0.0.0.0:8000
  fi
'
