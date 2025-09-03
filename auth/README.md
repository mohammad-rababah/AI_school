# Auth Microservice (with Facility Owners)

## 📌 Overview
The **Auth Microservice** is the entry point for identity and access management (IAA) in the platform.  
It provides secure authentication, onboarding, role-based access, and session management for:

- **Tutors** → Auth + Onboarding + Approval  
- **Students** → Fast entry  
- **Admins/Moderators** → Stronger security & RBAC  
- **Facility Owners** (Training centers, NGOs, universities, schools) → Auth + Facility onboarding + Multi-user management  

This service is built in **Golang** using:
- **Gin** (HTTP framework)
- **GORM** (ORM for database)
- **golang-migrate** (migrations)
- **JWT** (access & refresh tokens)
- **PostgreSQL** (primary database)
- **godotenv** (environment variable loader)

---

## 🏗️ Architecture

- **API Layer**: Gin routes grouped by user type (`/tutor/auth`, `/student/auth`, `/admin/auth`, `/facility/auth`)  
- **Database Layer**: PostgreSQL with GORM ORM  
- **Migrations**: SQL files under `/migrations` managed by `golang-migrate`  
- **Auth Layer**: JWT short-lived access tokens + rotating refresh tokens  
- **Session Management**: per-device sessions, revocation, audit logging  
- **Onboarding Layer**: tutors + facility owners go through approval flows  
- **Graceful Shutdown**: The server supports graceful shutdown on interrupt signals.  
- **Environment Variables**: Configuration is loaded from a `.env` file at startup.

---

## 📂 Project Structure

```
auth/
│
├── Dockerfile
├── go.mod
├── go.sum
├── main.go
├── .env
├── README.md
├── src/
│   ├── controller/    # HTTP handlers & route logic
│   ├── model/         # Data models (structs, DTOs)
│   ├── repo/          # Database/repository layer
│   ├── server/        # Server setup & configuration (Gin, graceful shutdown)
│   └── service/       # Business logic/services
│
```

---

## 🚦 Quick Start

1. Create a `.env` file with required variables (see example in repo).
2. Run `go run main.go` to start the service.
3. The server will listen on the port specified in `.env` (default: 8080).
4. Graceful shutdown is handled automatically on interrupt signals.

---

## 📊 Data Models

### User

| Field     | Type     | Notes |
|-----------|----------|-------|
| id        | int (pk) |       |
| email     | string   | unique |
| phone     | string   | unique |
| password  | string   | hashed |
| role      | enum(`tutor`, `student`, `admin`, `facility_owner`) | |
| status    | string   | lifecycle states |
| created_at | timestamp | |
| updated_at | timestamp | |

### Facility

| Field     | Type     | Notes |
|-----------|----------|-------|
| id        | int (pk) |       |
| owner_id  | int (fk→user.id) | |
| name      | string   | facility name |
| type      | enum(`training_center`, `ngo`, `university`, `school`) | |
| documents | JSONB    | uploaded docs |
| status    | string   | onboarding state |
| created_at | timestamp | |
| updated_at | timestamp | |

### Session

| Field     | Type     | Notes |
|-----------|----------|-------|
| id        | int (pk) | |
| user_id   | int (fk→user.id) | |
| device    | string   | device metadata |
| refresh_token | string | hashed |
| created_at | timestamp | |
| revoked   | bool     | |

---

## 🔐 Auth Flows

### Tutors
1. Register with email + phone (OTP).  
2. Verify both → status `VERIFIED`.  
3. Move to onboarding (subjects, certificates).  
4. Admin review → `APPROVED` or `REJECTED`.

### Students
1. Register with email OR phone (OTP).  
2. Verified immediately, no onboarding.  
3. Can browse/book tutors.

### Admins/Moderators
- Created by **super-admin** (no public signup).  
- Enforced **2FA** for login.  
- Role-based actions (moderation, finance, full control).

### Facility Owners
1. Register with **business email + phone**.  
2. Add **facility info** (type, name).  
3. Upload **documents** (license, accreditation, NGO certificate, etc.).  
4. Admin approval required.  
5. Approved owners can:
   - Create/manage tutors under their facility.  
   - Manage billing, reporting.  
   - Assign staff via RBAC.  

---

## 🛠️ API Endpoints

**Base URL:** `/api/v1`

### Tutors (`/tutor/auth`)
- `POST /register` — register with email, phone, password, name
- `POST /verify` — verify email or phone with OTP (single endpoint)
- `POST /login` — login with email or phone
- `POST /token/refresh` — refresh JWT tokens
- `POST /logout` — logout and invalidate session
- `GET /sessions` — list active sessions
- `DELETE /sessions/{id}` — delete a session
- `POST /password/reset/request` — request password reset
- `POST /password/reset/confirm` — confirm password reset with OTP
- `GET /status` — get tutor status (auth/onboarding state)  

---

### Students (`/student/auth`)
- Similar to tutors but simpler (no onboarding).  
- Optional: `POST /oauth/{provider}/callback`  

---

### Admins (`/admin/auth`)
- `POST /login`  
- `POST /token/refresh`  
- `POST /logout`  
- `GET /sessions`  
- `POST /2fa/setup | /confirm | /challenge`  
- `POST /password/reset/request`  
- `POST /password/reset/confirm`  

---

### Facility Owners (`/facility/auth`)
- `POST /init` — start signup (business email + phone)  
- `POST /verify/email`  
- `POST /verify/phone`  
- `POST /register` — finalize with password + facility info  
- `POST /login`  
- `POST /token/refresh`  
- `POST /logout`  
- `GET /sessions`  
- `DELETE /sessions/{id}`  
- `POST /onboarding/documents` — upload docs  
- `GET /status` — onboarding/approval state  
- (Post-Invest)  
  - `POST /2fa/setup | /confirm | /delete`  
  - RBAC endpoints: `/facility/auth/roles`  

---

## 📜 Migration Example

**0001_init_schema.up.sql**
```sql
CREATE TYPE user_role AS ENUM ('tutor','student','admin','facility_owner');
CREATE TYPE facility_type AS ENUM ('training_center','ngo','university','school');

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE,
    phone VARCHAR(20) UNIQUE,
    password TEXT NOT NULL,
    role user_role NOT NULL,
    status VARCHAR(50),
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP DEFAULT now()
);

CREATE TABLE facilities (
    id SERIAL PRIMARY KEY,
    owner_id INT REFERENCES users(id),
    name VARCHAR(255) NOT NULL,
    type facility_type NOT NULL,
    documents JSONB,
    status VARCHAR(50),
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP DEFAULT now()
);
```

---

## ⚙️ Conventions
- **JWT**: 15m access token, 30–90d rotating refresh token.  
- **Idempotency**: all POSTs accept `Idempotency-Key`.  
- **Localization**: `Accept-Language` header (AR/EN) supported.  
- **Security**:
  - Hash passwords (bcrypt/argon2).  
  - Hash OTPs & refresh tokens.  
  - Single-use links with TTL.  
- **Audit Events**:  
  - `user.created`, `user.login`, `user.logout`  
  - `facility.created`, `facility.approved`  

---

## 🚀 Running Locally
```bash
make migrate-up      # run migrations
go run cmd/main.go   # start Gin server
```
