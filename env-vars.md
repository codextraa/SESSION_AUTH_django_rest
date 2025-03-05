## Backend (Django) .env Setup

SECRET_KEY=Your Secret Key Here

APP_NAME=Your App Name

DEBUG=Boolean

TESTING=Boolean

HTTPS=Boolean

ENVIRONMENT="Development" or "Production"

BASE_ROUTE="/session-django-rest" (must be this unless frontend won't work)

DATABASE_ENGINE="django.db.backends.postgresql"

DATABASE_NAME=Your Database Name

DATABASE_USER=Your Database User

DATABASE_PASSWORD=Your Database Password

DATABASE_HOST="localhost"

DATABASE_PORT="5432"

EMAIL_HOST_USER=Your Email Host User

EMAIL_HOST_PASSWORD=Your Email Host Password

FRONTEND_URL="http://localhost:3000"

BACKEND_URL="http://localhost:8000"

HTTPS_BACKEND_URL="https://localhost"

HTTPS_FRONTEND_URL="https://localhost"

GOOGLE_CLIENT_ID=Your Google Client ID

GOOGLE_CLIENT_SECRET=Your Google Client Secret

FACEBOOK_CLIENT_ID=Your Facebook Client ID

FACEBOOK_CLIENT_SECRET=Your Facebook Client Secret

GITHUB_CLIENT_ID=Your GitHub Client ID

GITHUB_CLIENT_SECRET=Your GitHub Client Secret

TWILIO_ACCOUNT_SID=Your Twilio Account SID

TWILIO_AUTH_TOKEN=Your Twilio Auth Token

TWILIO_PHONE_NUMBER=Your Twilio Phone Number

RECAPTCHA_SITE_KEY=Your reCAPTCHA Site Key

RECAPTCHA_SECRET_KEY=Your reCAPTCHA Secret Key

## Frontend (NextJS) .env Setup

SECRET_KEY=Your Secret Key Here

AUTH_SECRET_KEY=Your Auth Secret Key Here

AUTH_SECRET=Your Auth Secret Here

NEXTAUTH_URL=https://localhost (if https) or http://localhost:3000 (if http)

NEXT_PUBLIC_AUTH_SECRET_KEY=Your Public Next Auth Secret Key Here

NODE_ENV=development or production

HTTPS=boolean

NEXT_PUBLIC_BASE_URL=http://localhost:3000

API_BASE_URL=http://localhost:8000/auth-api

MEDIA_BASE_URL=http://localhost:8000

NEXT_PUBLIC_BASE_HTTPS_URL=https://localhost

API_BASE_HTTPS_URL=https://localhost/auth-api

MEDIA_BASE_HTTPS_URL=https://localhost/media

GOOGLE_CLIENT_ID=Your Google Client ID

GOOGLE_CLIENT_SECRET=Your Google Client Secret

FACEBOOK_CLIENT_ID=Your Facebook Client ID

FACEBOOK_CLIENT_SECRET=Your Facebook Client Secret

GITHUB_CLIENT_ID=Your GitHub Client ID

GITHUB_CLIENT_SECRET=Your GitHub Client Secret

NEXT_PUBLIC_RECAPTCHA_SITE_KEY=Your reCAPTCHA Site Key
