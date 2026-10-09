# ATTENDO — backend starter + dark demo

This package contains the current dark-mode HTML demo, Attendo SVG logo, a FastAPI backend starter, PostgreSQL schema, and Docker Compose configuration.

## Run the backend locally

1. Install Docker Desktop or Docker Engine + Compose.
2. Copy `.env.example` values as appropriate; set strong secrets.
3. From this folder run `docker compose up --build`.
4. Open `http://localhost:8000/docs` and `http://localhost:8000/health`.

The Compose stack starts PostgreSQL and the API. Tables are created by SQLAlchemy on startup. The separate `database/schema.sql` documents the PostgreSQL table design.

## Current API starter

- `POST /auth/login` — institute code + user code + PIN
- `GET /me`
- `GET/PATCH /institute` — PATCH restricted to ADMIN
- `GET/POST /students` — POST restricted to ADMIN
- `GET/POST /sessions` — session list; POST restricted to ADMIN
- `GET/POST /sessions/{id}/attendance` — tenant checks and teacher-assignment checks
- `GET /audit` — ADMIN only
- `GET /health`

## Important: not yet Play Store ready

This is an implementation starter, **not a production-ready or validated release**. No production credentials, Firebase project, hosted API, Android Studio build, signing key, privacy policy, Data Safety declaration, or Play Console configuration were provided. Do not upload the HTML demo or this backend starter as if it were a compiled Android app.

Before real student data is used, a developer must add and test: user/institute provisioning and password/PIN reset; PostgreSQL row-level tenant isolation; robust immutable audit events; rate limiting; refresh/revocation; migration management; HTTPS; FCM push delivery; timetable/reminder scheduler; offline Room/WorkManager sync; PDF generation; full class/semester/subject model; backups/restore; tests; Kotlin Jetpack Compose Android client; signed APK/AAB; privacy/data deletion flows. Set `JWT_SECRET` to a strong random secret and remove all development defaults. The default SQLite option is only for local development.

## Logo

`branding/attendo-logo.svg` is the included logo artwork. It can be used in the web demo and exported into Android adaptive icon assets by the Android build pipeline.
