# LinkLoad Database Layer & Architecture Analysis

**A First Principles Deep Dive into a Security Scanning Platform**

---

## Table of Contents

1. [Database Fundamentals](#database-fundamentals)
2. [ORM Layer (SQLAlchemy)](#orm-layer-sqlalchemy)
3. [Supabase Integration](#supabase-integration)
4. [Authentication Flow](#authentication-flow)
5. [Application Flow](#application-flow)
6. [Architecture Overview](#architecture-overview)

---

# Database Fundamentals

## What is a Database in This Project?

At its core, a database is **persistent storage** that saves the state of the application so it survives beyond a single process lifetime. In LinkLoad, the database stores three categories of data:

1. **User data**: Credentials, profiles, account states
2. **Scan data**: Security scan records, results, metadata
3. **Vulnerability data**: Security findings, severity, locations

## How Database Initialization Works

### Phase 1: Application Startup (from `app/main.py`)

When the backend starts, the FastAPI application goes through a startup sequence:

```python
@app.on_event("startup")
async def startup_event():
    # Database tables already created by reset_db.py
    # Skip init_db() to avoid model import issues
    system_logger.info("Skipping database initialization (tables already exist)")
    
    # Initialize Redis cache
    from app.core.cache import cache_manager
    await cache_manager.initialize()
```

**Key insight**: The application assumes database tables already exist. This is a **separation of concerns** pattern—table creation is NOT a runtime operation but a **deployment-time** operation.

### Phase 2: Table Creation (Initialization Script)

Tables are created by `app/create_tables.py`:

```python
import os
from dotenv import load_dotenv
from sqlalchemy import create_engine
from app.models.attack_surface_models import Base

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)
Base.metadata.create_all(bind=engine)  # Creates all tables at once
print("Database tables created")
```

This script:
1. Loads environment variables (including `DATABASE_URL`)
2. Creates a SQLAlchemy **engine** (connection pool to database)
3. Calls `Base.metadata.create_all()` which:
   - Inspects all models imported from `app.models.*`
   - Compares their definitions to what exists in the database
   - Creates any missing tables using SQL `CREATE TABLE` statements

### Phase 3: What Actually Triggers Table Creation?

In development, typically:
- Manual script execution: `python app/create_tables.py`
- Docker image build (via Dockerfile)
- Database migration tools (Alembic, discussed below)

**In production**, table creation is typically a one-time setup, then only migrations are applied.

## How Schemas and Tables Are Created

### The Declarative Model Approach

SQLAlchemy uses a **declarative base** pattern. Each model is a Python class that maps to a database table:

```python
from sqlalchemy import Column, String, Boolean, DateTime, Integer
from app.database import Base  # This is declarative_base()

class User(Base):
    __tablename__ = "users"
    
    # Columns map to database columns
    id = Column(String, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
```

**What this means:**

| Python Class | Creates | In Database |
|---|---|---|
| `User` class | `users` table | PostgreSQL table with columns |
| `id` Column | `id` column | String/UUID primary key |
| `email` Column | `email` column | Unique string, not null |
| `created_at` Column | `created_at` column | Timestamp with timezone |

When `Base.metadata.create_all()` runs, SQLAlchemy generates equivalent SQL:

```sql
CREATE TABLE users (
    id VARCHAR PRIMARY KEY,
    email VARCHAR UNIQUE NOT NULL,
    username VARCHAR UNIQUE NOT NULL,
    hashed_password VARCHAR NOT NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX idx_users_email ON users(email);
```

### All Models in LinkLoad

The system imports these models to register them with the Base:

```python
from app.models.user import User, RevokedToken
from app.models.attack_surface_models import AttackSurfaceScan, DiscoveredAsset
from app.models.vulnerability_models import VulnerabilityData, VulnerabilityMitigation
from app.models.threat_intel_models import MITREData, MITREDatabase
```

**Tables created:**

| Model | Table Name | Purpose |
|---|---|---|
| `User` | `users` | User accounts, authentication |
| `RevokedToken` | `revoked_tokens` | Invalidated JWT tokens |
| `AttackSurfaceScan` | `attack_surface_scans` | Security scan metadata |
| `DiscoveredAsset` | `discovered_assets` | Findings from scans |
| `VulnerabilityData` | `vulnerabilities` | Vulnerability records |
| `VulnerabilityMitigation` | `vulnerability_mitigations` | Remediation guidance |
| Various MITRE tables | diverse | Threat intelligence mapping |

## How Migrations Are Managed

**Alembic** is the migration tool. It tracks schema changes over time:

```
alembic/
├── env.py          # Migration environment
├── script.py.mako  # Migration template
└── versions/       # Individual migration files
```

### The Migration System

1. **env.py** loads the database URL and target metadata:
   ```python
   database_url = os.getenv("DATABASE_URL", "sqlite:///app.db")
   config.set_main_option("sqlalchemy.url", database_url)
   target_metadata = Base.metadata  # Uses all declared models
   ```

2. **Migrations are versioned files** in `versions/` with timestamps

3. **Running migrations** applies pending schema changes:
   ```bash
   alembic upgrade head  # Apply all pending migrations
   ```

**Why use migrations instead of just `create_all()`?**

- **Version control**: Schema changes are tracked like code
- **Reversibility**: Can rollback to previous schema states
- **Team collaboration**: Multiple developers can apply same changes consistently
- **Audit trail**: Know exactly when each schema change happened

### Current Implementation Note

The project uses **manual table creation** rather than migrations for initial setup:
```python
# In database.py
def init_db():
    """Initialize database tables"""
    Base.metadata.create_all(bind=engine)
```

This is simpler for early development but would make it harder to track schema evolution.

## How Data Flows from Application to Database

### Request → Processing → Storage Flow

Let's trace a user registration:

```
1. HTTP Request
   └─→ POST /api/v1/auth/register
       { email: "user@example.com", password: "SecurePass123!" }

2. FastAPI receives request
   └─→ Calls register_user() endpoint function
       └─→ Dependency injection: get_db() creates database Session
           (Session = connection to database that can execute queries)

3. Validation & Processing
   └─→ Python validates input (Pydantic models)
   └─→ Query database: "Does this email already exist?"
       db.query(User).filter(User.email == email).first()
       └─→ This becomes SQL: SELECT * FROM users WHERE email = ?
       └─→ Database executes, returns result or None

4. Data Modification
   └─→ Hash password with bcrypt
   └─→ Create Python object: db_user = User(email=..., hashed_password=...)
   └─→ Add to session: db.add(db_user)
   └─→ Commit transaction: db.commit()
       └─→ SQLAlchemy converts to: INSERT INTO users (email, ...) VALUES (...)
       └─→ Database executes INSERT, returns auto-generated id
       └─→ Transaction completes, changes are permanent

5. Response
   └─→ Refresh object from DB: db.refresh(db_user)
   └─→ Convert to response model: UserResponse.model_validate(db_user)
   └─→ Return to client as JSON
```

### Key Concepts in This Flow

**Sessions**: A session is a **transaction container**. All queries within one session are grouped into a single database transaction:

```python
def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()  # Create new session
    try:
        yield db  # FastAPI injects into route handler
    finally:
        db.close()  # Session cleaned up after request
```

**Transactions**: A transaction is **atomic** (all-or-nothing):
- If `db.commit()` succeeds: ALL changes in session are permanent
- If an exception occurs: `db.rollback()` cancels all pending changes
- This prevents partial data corruption

**Queries**: SQLAlchemy translates Python code to SQL:

```python
# Python (SQLAlchemy ORM)
user = db.query(User).filter(User.email == "test@example.com").first()

# Becomes SQL
SELECT * FROM users WHERE email = 'test@example.com' LIMIT 1

# Database executes and returns matching row(s)
```

## Data Flow Deep Dive: Reading Data

When a user views their past scans:

```
1. Parse Authentication Token
   └─→ Header: Authorization: Bearer eyJhbGc...
   └─→ Extract token, verify signature with SECRET_KEY
   └─→ Decode JWT payload: { sub: "user-id-123", exp: ..., jti: ... }
   └─→ Result: current_user_id = "user-id-123"

2. Query Database
   └─→ db.query(Scan).filter(
           Scan.user_id == "user-id-123"
       ).order_by(Scan.created_at.desc()).all()
   └─→ SQL: SELECT * FROM owasp_scans 
            WHERE user_id = 'user-id-123'
            ORDER BY created_at DESC

3. Database Returns Rows
   └─→ Multiple rows as Python dictionaries/ORM objects
   └─→ SQLAlchemy maps each row to a Scan model instance

4. Transform & Return
   └─→ Convert ORM objects to Pydantic response models
   └─→ Return as JSON array to client
```

---

# ORM Layer (SQLAlchemy)

## What is an ORM?

**ORM = Object-Relational Mapping**

A bridge between object-oriented Python code and relational SQL databases:

```
Python World                SQL World
─────────────────          ──────────────
user = User()    ────→     INSERT INTO users
user.email       ────→     users.email column
user.save()      ────→     COMMIT transaction
```

Benefits:
- Write Python instead of SQL strings
- Type safety (catch errors at development time)
- Automatic query optimization
- Protection against SQL injection

## SQLAlchemy Architecture in LinkLoad

### The Core Components

```python
# 1. Engine: Connection Pool
engine = create_engine(
    DATABASE_URL,
    pool_size=10,           # Keep 10 connections open
    max_overflow=20,        # Allow 20 extra in spike
    pool_pre_ping=True      # Test connections before using
)

# 2. SessionLocal: Factory for Sessions
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 3. Base: Registry of all models
Base = declarative_base()

# 4. Dependency for FastAPI
def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
```

### How These Work Together

```
Request arrives
    ↓
FastAPI route needs database
    ↓
Call get_db() dependency
    ↓
SessionLocal() creates Session
    ↓
Session gets connection from Engine's connection pool
    ↓
Session.query(Model) creates query builder
    ↓
Execute SQL via connection
    ↓
Map results to Python objects
    ↓
Route handler processes objects
    ↓
Explicit commit() or rollback()
    ↓
Session.close() returns connection to pool
    ↓
Response sent to client
```

## How Models Map to Tables

### The Declaration

```python
class VulnerabilityData(Base):
    __tablename__ = "vulnerabilities"
    
    # Primary key
    id = Column(Integer, primary_key=True, index=True)
    
    # Data columns
    title = Column(String, nullable=False)
    severity = Column(Float, nullable=False)
    cvss_score = Column(Float)
    description = Column(String)
    
    # Timestamps
    created_at = Column(DateTime, default=utc_now_naive)
    updated_at = Column(DateTime, onupdate=utc_now_naive)
    
    # Relationships (Foreign Keys)
    asset_id = Column(Integer, ForeignKey('discovered_assets.id'))
    asset = relationship("DiscoveredAsset", back_populates="vulnerabilities")
```

### Mapping Explained

| Python Type | Database Type | Meaning |
|---|---|---|
| `String` | `VARCHAR` | Variable-length text |
| `Integer` | `INT` | Whole numbers |
| `Float` | `FLOAT` | Decimal numbers |
| `DateTime` | `TIMESTAMP` | Date and time |
| `JSON` | `JSONB` (Postgres) | Nested data structures |
| `Boolean` | `BOOLEAN` | True/False |
| `ForeignKey` | `CONSTRAINT` | Link to another table |

### Relationships

LinkLoad uses **relationships** to connect tables:

```python
# One-to-Many: One User → Many Scans
class Scan(Base):
    user_id = Column(String, ForeignKey('users.id'))
    # Back_populates creates reverse relationship
    user = relationship("User", back_populates="scans")

# One-to-Many: One Scan → Many Vulnerabilities
class Vulnerability(Base):
    scan_id = Column(String, ForeignKey('owasp_scans.scan_id'))
    scan = relationship("Scan", back_populates="vulnerabilities")
```

When you access: `scan.vulnerabilities`, SQLAlchemy automatically:
1. Queries the vulnerabilities table
2. Filters WHERE scan_id = this_scan.id
3. Returns results as Python objects

```python
scan = db.query(Scan).get(scan_id)
vulns = scan.vulnerabilities  # Automatic join & filter
# Becomes: SELECT * FROM owasp_vulnerabilities 
#          WHERE scan_id = scan_id
```

## How Queries Work Internally

### Query Execution Steps

```python
# Step 1: Build query
query = db.query(User).filter(User.email == "test@example.com")

# Step 2: Generate SQL
sql = "SELECT * FROM users WHERE email = %s"
params = ("test@example.com",)

# Step 3: Send to database
cursor = connection.execute(sql, params)

# Step 4: Fetch results
rows = cursor.fetchall()
# Result: [{"id": "123", "email": "test@example.com", ...}]

# Step 5: Map to Python objects
user_objects = [User(**row) for row in rows]

# Step 6: Return
result = user_objects[0]  # From .first()
```

### Query Types

**SELECT (Reading Data)**
```python
# Get one user
user = db.query(User).filter(User.id == "123").first()

# Get all users
users = db.query(User).all()

# Get with conditions
vulns = db.query(Vulnerability).filter(
    Vulnerability.severity == "critical"
).all()

# OrderBy and limit
recent = db.query(Scan).order_by(Scan.created_at.desc()).limit(10).all()
```

**INSERT (Writing Data)**
```python
new_user = User(email="new@example.com", username="newuser")
db.add(new_user)  # Stage the insert
db.commit()       # Execute: INSERT INTO users (email, username) VALUES (...)
db.refresh(new_user)  # Re-fetch to get auto-generated ID
```

**UPDATE (Modifying Data)**
```python
user = db.query(User).get("123")
user.email = "newemail@example.com"  # Python object change
db.commit()  # Execute: UPDATE users SET email = ... WHERE id = '123'
```

**DELETE (Removing Data)**
```python
db.query(User).filter(User.id == "123").delete()
db.commit()  # Execute: DELETE FROM users WHERE id = '123'
```

## How Transactions Work Internally

### The Transaction Lifecycle

```
Session Created
    ↓
BEGIN TRANSACTION (implicit)
    ↓
Queries execute within transaction context
    ↓
Modifications staged in session
    ↓
db.commit() called
    ↓
COMMIT TRANSACTION sent to database
    ↓
All changes become permanent
```

### Why Transactions Matter

Without transactions:
```python
# DANGER: If error occurs after insert but before scans clean, data corruption
scan = create_scan()                    # INSERT scan
vulns = insert_vulnerabilities(scan)    # INSERT vulns
cleanup_old_data()                      # Bug! Deletes wrong data
# Inconsistent state: scan exists but with wrong vulns
```

With transactions (all-or-nothing):
```python
try:
    scan = create_scan()                    # Staged
    vulns = insert_vulnerabilities(scan)    # Staged
    cleanup_old_data()                      # Staged
    db.commit()                             # All execute together
except Exception:
    db.rollback()  # NOTHING executes, back to consistent state
```

### Automatic Transaction Management

```python
def get_db_context():
    """Context manager for background tasks"""
    db = SessionLocal()
    try:
        yield db
        db.commit()  # Commit if no exception
    except Exception:
        db.rollback()  # Rollback if exception
        raise
    finally:
        db.close()
```

Used when the operation might not go through FastAPI's dependency system:

```python
# In background task
with get_db_context() as db:
    # ... operations ...
    # Automatically committed or rolled back
```

---

# Supabase Integration

## What is Supabase?

Supabase is a **Backend-as-a-Service** (BaaS) that provides:

| Service | What It Does |
|---|---|
| **PostgreSQL Database** | Managed Postgres database in cloud |
| **Authentication (Auth)** | User sign-up, login, magic links, OAuth |
| **Storage** | File uploads (images, documents) |
| **Realtime** | WebSocket subscriptions to data changes |
| **Vector DB** | Embeddings for AI features |

LinkLoad uses primarily the **Database** and **Auth** services.

## How Supabase is Connected

### Connection Configuration

```python
# app/core/config.py
SUPABASE_URL: str = Field(..., description="Supabase project URL")
SUPABASE_KEY: str = Field(..., description="Supabase public API key")
SUPABASE_SERVICE_KEY: str = Field(..., description="Supabase service role API key")
DATABASE_URL: str = "postgresql://user:password@host:port/database"
```

From `.env`:
```
SUPABASE_URL=https://hpowvsuennnaqbqdbuet.supabase.co
SUPABASE_KEY=sb_publishable_yycHAGFh6Jiv2E-EG9mNCQ_RN2oA-Qn
DATABASE_URL=postgresql://postgres:password@aws-0-ap-south-1.pooler.supabase.com:6543/postgres
```

### Two Supabase Client Instances

```python
class SupabaseClient:
    def __init__(self):
        # Public client (user-scoped, RLS enforced)
        self.client: Client = create_client(
            settings.SUPABASE_URL, 
            settings.SUPABASE_KEY
        )
        
        # Admin client (service-role, RLS bypassed)
        self.admin: Client = create_client(
            settings.SUPABASE_URL, 
            settings.SUPABASE_SERVICE_KEY
        )
        
        # SQLAlchemy engine for raw SQL (direct DB access)
        self.engine = create_engine(db_url)
        self.Session = sessionmaker(bind=self.engine)
```

**Why two clients?**

| Client | Access Level | When Used |
|---|---|---|
| `client` | User-scoped | Frontend operations, user must authenticate |
| `admin` | Full access | Backend operations, server is trusted |

### The Database Connection URL

```
postgresql://user:password@host:port/database?sslmode=require
```

Breaks down to:
- `postgresql://` - Use Postgres driver
- `user:password` - Credentials
- `host:port` - AWS Postgres instance
- `database` - Database name (usually `postgres`)
- `sslmode=require` - Encrypt all connections (security)

## Supabase Services Used

### 1. PostgreSQL Database

The actual data storage. LinkLoad uses the Postgres backend directly:

```python
# Direct SQL execution
with self.Session() as session:
    result = session.execute(
        text("SELECT * FROM users WHERE email = :email"),
        {"email": email}
    )
    user = result.scalar_one_or_none()
```

**Tables created in Postgres:**

```sql
-- User management
CREATE TABLE users (
    id VARCHAR PRIMARY KEY,
    email VARCHAR UNIQUE NOT NULL,
    username VARCHAR UNIQUE NOT NULL,
    hashed_password VARCHAR NOT NULL,
    is_verified BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ...
);

-- Token revocation
CREATE TABLE revoked_tokens (
    jti VARCHAR PRIMARY KEY,
    token_type VARCHAR NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    ...
);

-- Scan records
CREATE TABLE owasp_scans (
    scan_id VARCHAR PRIMARY KEY,
    user_id VARCHAR NOT NULL REFERENCES users(id),
    target_url VARCHAR NOT NULL,
    status VARCHAR DEFAULT 'pending',
    ...
);

-- Vulnerability findings
CREATE TABLE owasp_vulnerabilities (
    id SERIAL PRIMARY KEY,
    scan_id VARCHAR NOT NULL REFERENCES owasp_scans(scan_id),
    title VARCHAR NOT NULL,
    severity VARCHAR NOT NULL,
    cvss_score FLOAT,
    ...
);
```

### 2. Authentication (Token Management)

Supabase Auth tokens are validated, but LinkLoad implements its own JWT tokens:

```python
# Create custom JWT
access_token = security_manager.create_access_token(subject=user.id)
# Payload: { exp: ..., sub: user_id, jti: unique_id, type: "access" }
# Signed with settings.SECRET_KEY

# Validate token
payload = security_manager.verify_token(token)
# Checks signature, expiration, revocation list
```

**Token Revocation Flow:**

```python
# When user logs out
def logout(user_id: str):
    # Extract token's jti (unique identifier)
    jti = payload.get("jti")
    expires_at = payload.get("exp")
    
    # Add to revocation list
    supabase.revoke_token(jti, expires_at)
    # Inserts into database: INSERT INTO revoked_tokens (jti, expires_at)
    
    # Check on next request
    if supabase.is_token_revoked(jti):
        # Reject request, token is revoked
        raise AuthenticationException("Token revoked")
```

### 3. Storage (Not Currently Used for Scans)

Supabase Storage is designed for file uploads. LinkLoad currently stores:
- Scan results in database (serialized JSON)
- Temporary files in memory cache
- Reports on filesystem

But could use Supabase Storage for:
- Large reports
- Evidence files
- Screenshot artifacts

## How Supabase Differs from Self-Managed Database

### Supabase-Managed

```
Your Application ←→ Supabase Cloud ←→ AWS PostgreSQL
                    (Handles backups, scaling, monitoring)
```

**Advantages:**
- ✅ Automatic backups
- ✅ Automatic scaling
- ✅ Built-in authentication
- ✅ Realtime subscriptions
- ✅ No DevOps overhead

**Disadvantages:**
- ❌ Network latency (calls over HTTPS)
- ❌ Vendor lock-in
- ❌ Pricing per request
- ❌ Less control over connection pools

### Self-Managed Database

```
Your Application ←→ Your Postgres Server (on your machine/VPS)
```

**Advantages:**
- ✅ Low latency (local network)
- ✅ Full control over configuration
- ✅ No per-request fees
- ✅ Can implement unusual requirements

**Disadvantages:**
- ❌ Must manage backups manually
- ❌ Must handle scaling yourself
- ❌ Must monitor uptime
- ❌ Security responsibility on you

## Fallback System (In-Memory Cache)

LinkLoad has a **fallback system** when Supabase is unavailable:

```python
class SupabaseClient:
    def __init__(self):
        self._memory_scans: Dict[str, Dict] = {}
        self._memory_vulns: Dict[str, List[Dict]] = {}
    
    def create_scan(self, record: Dict) -> Optional[Dict]:
        """Insert scan - tries DB, falls back to memory"""
        try:
            res = self.admin.table("owasp_scans").insert(record).execute()
            self._memory_scans[record["scan_id"]] = res.data[0]
            return res.data[0]
        except Exception:
            # Fallback: store in memory
            self._memory_scans[record["scan_id"]] = record
            return record
    
    def fetch_scan(self, scan_id: str) -> Optional[Dict]:
        """Fetch scan - tries DB, falls back to memory"""
        try:
            res = self.admin.table("owasp_scans").select("*").eq("scan_id", scan_id).execute()
            return res.data[0] if res.data else None
        except Exception:
            # Fallback: read from memory
            return self._memory_scans.get(scan_id)
```

**Why this matters:**

- Application can continue in degraded mode
- Scans don't fail completely if DB is slow
- Data is preserved until DB comes back online
- Data in memory is eventually synced to DB

This is **high availability** (HA) design—trading eventual consistency for availability.

---

# Authentication Flow

## End-to-End Authentication Architecture

Authentication in LinkLoad has multiple layers:

```
Request arrives with Authorization header
    ↓
Extract JWT token from header
    ↓
Verify token signature with SECRET_KEY
    ↓
Check if token is revoked (in database)
    ↓
Extract user ID from token payload
    ↓
Verify user still exists in database
    ↓
Grant access, inject user into route handler
```

## Token Structure & JWTs

### What is a JWT?

A JWT (JSON Web Token) is a **signed, self-contained token**:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiJ1c2VyLWlkLTEyMyIsImV4cCI6MTcwMDAwMDAwMCwianRpIjoiYWJjZGVmIn0.
HmacSHA256(header.payload, secret_key)
```

Three parts separated by dots:

**Part 1: Header**
```json
{"alg": "HS256", "typ": "JWT"}
```
(Base64 encoded)

**Part 2: Payload**
```json
{
    "sub": "user-id-123",      // Subject (user ID)
    "exp": 1700000000,         // Expiration (Unix timestamp)
    "jti": "abcdef",           // JWT ID (unique identifier)
    "type": "access",          // Token type (access or refresh)
    "iat": 1699913600          // Issued at
}
```
(Base64 encoded)

**Part 3: Signature**
```
HMAC-SHA256(
    base64(header) + "." + base64(payload),
    "SECRET_KEY_VALUE"
)
```
(Base64 encoded)

### How JWT Validation Works

```python
def verify_token(token: str) -> Optional[dict]:
    try:
        # Decode and verify signature
        payload = jwt.decode(
            token, 
            settings.SECRET_KEY,  # Secret key for verification
            algorithms=["HS256"]   # Algorithm must match
        )
        # If signature doesn't match or someone tampered: raises JWTError
        
        # Check if token is revoked
        if supabase.is_token_revoked(payload.get("jti")):
            return None  # Token was logged out
        
        return payload  # Valid! Return decoded data
    except JWTError:
        return None  # Invalid signature
```

**The signature proves:**
- Token wasn't modified by the client
- Only the backend (which knows SECRET_KEY) could have created it

### Token Types: Access vs Refresh

**Access Token** (short-lived, ~7 days)
- Used for API requests
- Sent in Authorization header
- Changes less frequently (reduces DB queries)
- If leaked, limited damage window

**Refresh Token** (long-lived, 30 days)
- Only used to get new access token
- Stored securely (HttpOnly cookie or localStorage)
- If stolen, attacker can renew tokens

## User Registration Flow (Step-by-Step)

```
1. Client sends HTTP POST /api/v1/auth/register
   Body: {
     email: "user@example.com",
     username: "newuser",
     password: "SecurePass123!",
     confirm_password: "SecurePass123!"
   }

2. FastAPI receives request
   ↓ Dependency: get_db() creates database session
   ↓ Pydantic validation (see UserCreate model)

3. Input Validation
   ├─ Email format valid? ✓
   ├─ Username 3-50 chars? ✓
   ├─ Password contains:
   │  ├─ At least 12 characters? ✓
   │  ├─ Uppercase letter? ✓
   │  ├─ Lowercase letter? ✓
   │  ├─ Digit? ✓
   │  └─ Special character? ✓
   └─ Passwords match? ✓

4. Check Email Uniqueness
   SQL: SELECT * FROM users WHERE email = 'user@example.com'
   Result: None (good, email not taken)

5. Check Username Uniqueness
   SQL: SELECT * FROM users WHERE username = 'newuser'
   Result: None (good, username not taken)

6. Hash Password
   plain = "SecurePass123!"
   salt = generate_random_salt()
   hashed = bcrypt(plain, salt)
   → "$2b$12$R9h7cIPz0giKuRiAJXz0IuEFI.PzNQVSPq4R5VqmvZ3P0rqPG3BWm"
   
   (bcrypt uses salt to make each hash unique even for same password)

7. Create User Object
   user_obj = User(
       id=generate_uuid(),
       email="user@example.com",
       username="newuser",
       hashed_password="$2b$12$...",
       is_active=True,
       is_verified=False,  ← Email not yet confirmed
       created_at=now()
   )

8. Insert into Database
   db.add(user_obj)
   db.commit()
   SQL: INSERT INTO users (id, email, username, hashed_password, ...)
        VALUES ('123abc', 'user@example.com', 'newuser', '$2b$12$...', ...)
   
   Database executes, returns success

9. Refresh Object (get auto-generated fields)
   db.refresh(user_obj)
   SQL: SELECT * FROM users WHERE id = '123abc'

10. Generate Tokens
    access_token = create_access_token(subject=user_obj.id)
    → Payload: {sub: '123abc', exp: now+7days, jti: 'abcef', type: 'access'}
    → Signed with SECRET_KEY
    → Result: "eyJhbGc..."
    
    refresh_token = create_refresh_token(subject=user_obj.id)
    → Payload: {sub: '123abc', exp: now+30days, jti: 'xyz123', type: 'refresh'}
    → Signed with SECRET_KEY
    → Result: "eyJhbGc..."

11. Build Response
    return {
        user: {id, email, username, is_verified, ...},
        access_token: "eyJhbGc...",
        refresh_token: "eyJhbGc...",
        expires_in: 604800  ← seconds (7 days)
    }

12. Send to Client
    HTTP 201 Created
    Body: JSON response
    Set-Cookie: refresh_token=...; HttpOnly; Secure; SameSite=Strict
    (best practice: refresh token in secure cookie, not response body)

13. Client stores tokens
    - access_token: in memory or sessionStorage (accessible to JS)
    - refresh_token: in HttpOnly cookie (NOT accessible to JS, safer)
    
    On subsequent requests:
    Authorization: Bearer eyJhbGc...
```

### Why is password hashing necessary?

**Scenario: Database is breached**

Without hashing:
```
Database stolen: users = {email: "user@ex.com", password: "SecurePass123!"}
Attacker reads password, logs in as that user
Attacker accesses all user data
```

With hashing:
```
Database stolen: users = {email: "user@ex.com", password: "$2b$12$R9h7..."}
Attacker sees hash, cannot reverse it
Attacker tries to log in with hash: incorrect (hash != password)
Safety preserved
```

Bcrypt specifically:
- Slow (intentionally, 2^12 rounds)
- Unique (uses salt per user)
- Adaptive (can increase rounds over time)

## User Login Flow (Step-by-Step)

```
1. Client sends HTTP POST /api/v1/auth/login
   Body: {
     email: "user@example.com",
     password: "SecurePass123!"
   }

2. Validate Input
   ├─ Email format valid? ✓
   └─ Password provided? ✓

3. Query Database for User
   SQL: SELECT * FROM users WHERE email = 'user@example.com'
   
   If not found:
   → Return generic error: "Invalid username or password"
      (Don't reveal if email exists, prevents email enumeration)
   → Log authentication attempt (for security auditing)
   → Increment suspicious activity counter
   
   Result: user object or None

4. Check Account Status
   If user.locked_until > now():
   → Return error: "Account locked after repeated failures"
   → Prevent brute force attacks (5 failed attempts = 15 min lockout)
   
   If not user.is_active:
   → Return error: generic
   → Prevent login to suspended accounts

5. Verify Password
   provided_password = "SecurePass123!"
   stored_hash = "$2b$12$R9h7..."
   
   if bcrypt.verify(provided_password, stored_hash):
       ✓ Correct password
   else:
       ✗ Wrong password
       
   Increment failed_login_attempts counter
   if failed_login_attempts >= 5:
       Set locked_until = now + 15 minutes
       Save to database
       Return error
   
   Save attempt to database

6. Successful Login
   Reset failed_login_attempts = 0
   Clear locked_until = None
   Set last_login = now()
   
   SQL: UPDATE users 
        SET failed_login_attempts=0, locked_until=NULL, last_login=now()
        WHERE id='123abc'

7. Generate Tokens
   (same as registration)
   access_token, refresh_token with user ID embedded

8. Return Response
   Status: 200 OK
   Body: {user, access_token, refresh_token, expires_in}

9. Log Authentication Event
   Log: {
       user_id: '123abc',
       email: 'user@example.com',
       ip_address: '192.168.1.1',
       success: true,
       timestamp: now()
   }
   (for security audit trail)
```

## Token Refresh Flow

```
1. Client has expired access_token: "eyJhbGc..." (token.exp < now)
   Client still has valid refresh_token: "eyJhbGc..."

2. POST /api/v1/auth/refresh
   Body: {refresh_token: "eyJhbGc..."}

3. Verify Refresh Token
   payload = verify_token(refresh_token)
   
   Checks:
   ├─ Signature valid with SECRET_KEY? (untampered)
   ├─ Token expired? (now < exp)
   ├─ Token type = "refresh"? (not an access token)
   └─ Token in revocation list? (not logged out)
   
   If any check fails: raise AuthenticationException

4. Check User Still Exists
   user = db.query(User).filter(User.id == payload.sub).first()
   
   If not found or is_active=false:
   → Return error: "User not found or inactive"
   → Prevent creating tokens for deleted accounts

5. Generate New Access Token
   new_access_token = create_access_token(
       subject=payload.sub,
       expires_delta=7 days
   )
   
   Payload: {sub: user_id, exp: now+7days, jti: new_uuid, type: 'access'}
   Signed with SECRET_KEY

6. Return New Access Token
   Status: 200 OK
   Body: {
       access_token: "eyJhbGM...", ← New access token
       refresh_token: refresh_token,  ← Same refresh token
       expires_in: 604800
   }
   
   Note: Refresh token typically doesn't rotate (lasts 30 days)
         Could implement rotating refresh tokens for extra security

7. Client Updates
   - Stores new access_token (short-lived, 7 days)
   - Keeps refresh_token (long-lived, 30 days)
   - Can now make requests with new access_token
```

## Token Logout (Revocation) Flow

```
1. Client sends POST /api/v1/auth/logout
   Header: Authorization: Bearer eyJhbGc... (access token)

2. Extract Token from Header
   Extract "eyJhbGc..." from "Bearer eyJhbGc..."

3. Verify Token is Valid
   payload = verify_token(token)
   
   If token invalid/expired:
   → Still return 204 (success - logout intention achieved)
   → Logout is idempotent

4. Extract Token Metadata
   jti = payload.get("jti")  ← "abcdef"
   exp = payload.get("exp")  ← 1700000000

5. Add to Revocation List
   SQL: INSERT INTO revoked_tokens (jti, token_type, revoked_at, expires_at)
        VALUES ('abcdef', 'access', now(), unix_timestamp(1700000000))
   
   This token ID is now blacklisted

6. On Next Request with Same Token
   old_token = "eyJhbGc..." (jti=abcdef)
   payload = verify_token(old_token)  ← Signature still valid!
   
   Check revocation: is_token_revoked(payload["jti"])
   SQL: SELECT 1 FROM revoked_tokens 
        WHERE jti='abcdef' AND expires_at > now()
   
   Result: Yes, revoked
   → Return: "Token revoked"
   → Request rejected

7. Cleanup (Optional)
   Periodically delete expired entries:
   SQL: DELETE FROM revoked_tokens WHERE expires_at < now()
```

## Authenticated User Linking to Database

### How Identity Flows Through the System

```
Database Layer:
┌─────────────────────────────────┐
│  users table                    │
├─────────────────────────────────┤
│ id      (PK): "user-id-123"     │
│ email   : "user@example.com"    │
│ username: "newuser"             │
│ ...                             │
└─────────────────────────────────┘
          ↑ References
          │
┌─────────────────────────────────┐
│  owasp_scans table              │
├─────────────────────────────────┤
│ scan_id (PK): "scan-456"        │
│ user_id (FK): "user-id-123" ←───┼── Links scan to owner
│ target_url : "https://..."      │
│ status     : "completed"        │
│ ...                             │
└─────────────────────────────────┘

Application Layer:
current_user_id = "user-id-123"
    ↓ (from validated JWT token)
    │
Query: db.query(Scan).filter(
            Scan.user_id == current_user_id
        ).all()
    ↓ (SQL: SELECT * FROM owasp_scans WHERE user_id = 'user-id-123')
    ↓
Result: [Scan object 1, Scan object 2, ...]
    ↓ (Only this user's scans, not global)
    ↓
Return to client
```

### Authorization Pattern

Every operation checks ownership:

```python
@router.get("/scans/{scan_id}")
async def get_scan(
    scan_id: str,
    current_user = Depends(get_current_user),  # Gets user from token
    db: Session = Depends(get_db)
):
    # Get scan from database
    scan = db.query(Scan).get(scan_id)
    
    # Verify ownership
    if scan.user_id != current_user.id:
        raise AccessDeniedException("You don't own this scan")
    
    return ScanResponse.from_orm(scan)
```

This pattern prevents:
- User A accessing User B's scans
- User A modifying User B's data
- User A deleting User B's scans

---

# Application Flow

## Step-by-Step: System Startup

```
1. Docker container starts
   └─→ CMD: uvicorn app.main:app --host 0.0.0.0 --port 8000

2. Python imports app.main module
   └─→ Imports all dependencies
   └─→ Creates FastAPI app instance
   └─→ Adds middleware stack
   └─→ Registers routers (endpoints)

3. FastAPI initializes (before handling requests)
   └─→ Instantiates app = FastAPI(...)

4. await startup_event() called
   ├─→ Log: "Skipping database initialization (tables already exist)"
   ├─→ Initialize Redis cache
   │  └─→ redis.ping() to verify connection
   │  └─→ Log: "Redis cache initialized successfully"
   └─→ Log: "Application startup complete"

5. Server listening
   ├─→ uvicorn server starts on 0.0.0.0:8000
   ├─→ Ready to receive HTTP requests
   └─→ Log: "Started server process [PID]"

6. On Shutdown
   └─→ await shutdown_event() called
   ├─→ Close Redis connections
   ├─→ Stop background cleanup tasks
   └─→ Graceful shutdown complete
```

### Database State at Startup

Tables already exist in Postgres:
```
Supabase PostgreSQL
├─ users
├─ revoked_tokens
├─ owasp_scans
├─ owasp_vulnerabilities
├─ domains
└─ ... (all tables from models)
```

The application assumes this, doesn't recreate them.

## Step-by-Step: User Sign-Up Request

```
1. Client sends request
   POST /api/v1/auth/register HTTP/1.1
   Host: localhost:8000
   Content-Type: application/json
   
   {
     "email": "newuser@example.com",
     "username": "newuser",
     "password": "SecurePass123!",
     "confirm_password": "SecurePass123!",
     "full_name": "New User"
   }

2. Network routing
   ├─→ Request reaches backend service (8000)
   └─→ FastAPI receives

3. Middleware stack processes request
   ├─→ GZipMiddleware: Check if compression needed? (No, small request)
   ├─→ TrustedHostMiddleware: Is Host header valid? (Yes: localhost:8000)
   ├─→ InjectionPreventionMiddleware: Check for injection patterns? (No)
   ├─→ SecurityHeadersMiddleware: Process security headers? (Yes)
   └─→ Custom middleware: Add request ID, log request

4. Route matching
   ├─→ FastAPI matches: POST /api/v1/auth/register
   └─→ Calls: register_user(request, user_data, db)

5. Dependency injection
   ├─→ Request Depends(get_db)
   │  └─→ Creates SessionLocal()
   │  └─→ Gets connection from engine pool
   │  └─→ Returns session (yields into handler)
   └─→ user_data: Pydantic parses JSON body into UserCreate model
      └─→ Validates each field
      └─→ Checks email format, password strength, etc.
      └─→ If any validation fails: returns 422 Unprocessable Entity

6. Handler execution: register_user()
   
   Inside the function:
   a. Normalize input
      email = "newuser@example.com".strip().lower()
      username = "newuser".strip().lower()
   
   b. Check email not taken
      SQL: SELECT * FROM users WHERE email = 'newuser@example.com'
      Result: None ✓
   
   c. Check username not taken
      SQL: SELECT * FROM users WHERE username = 'newuser'
      Result: None ✓
   
   d. Hash password
      hashed = bcrypt.hashpw(
          b"SecurePass123!",
          bcrypt.gensalt()
      )
      Result: b'$2b$12$R9h7cIPz0...'
   
   e. Create User object (not yet in DB)
      db_user = User(
          id=str(uuid.uuid4()),  ← Generate unique ID
          email='newuser@example.com',
          username='newuser',
          full_name='New User',
          hashed_password='$2b$12$R9h7cIPz0...',
          is_active=True,
          is_verified=False
      )
   
   f. Stage insert in transaction
      db.add(db_user)
      (This doesn't execute SQL yet, just stages it)
   
   g. Commit transaction
      db.commit()
      └─→ SQLAlchemy generates:
          INSERT INTO users (id, email, username, full_name, 
                           hashed_password, is_active, is_verified)
          VALUES ('abc123def', 'newuser@example.com', 'newuser', 
                  'New User', '$2b$12$R9h7...', true, false)
      └─→ Database executes
      └─→ Row inserted, transaction committed
   
   h. Refresh object (fetch generated fields)
      db.refresh(db_user)
      └─→ Re-fetches user from DB
      └─→ Ensures object has any DB-generated values
   
   i. Generate tokens
      access_token = create_access_token(subject=db_user.id)
      → Encodes: { sub: 'abc123def', exp: now+7d, jti: 'xyz789', type: 'access' }
      → Hmacs with SECRET_KEY
      → Returns base64: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.etc...'
      
      refresh_token = create_refresh_token(subject=db_user.id)
      → Encodes: { sub: 'abc123def', exp: now+30d, jti: 'abc789', type: 'refresh' }
      → Hmacs with SECRET_KEY
      → Returns base64
   
   j. Build response
      response = UserWithTokens(
          user=UserResponse(
              id='abc123def',
              email='newuser@example.com',
              username='newuser',
              is_verified=False,
              ...
          ),
          access_token='eyJ...',
          refresh_token='eyJ...',
          expires_in=604800
      )

7. Database connection cleanup
   └─→ Finally block in get_db() executes
   └─→ db.close()
   └─→ Connection returned to pool
   └─→ Not closed, just idle (for reuse)

8. Response serialization
   ├─→ Convert UserWithTokens to JSON
   ├─→ Timestamps to ISO format strings
   └─→ All fields serializable

9. Response middleware processing
   ├─→ SecurityHeadersMiddleware: Add security headers
   ├─→ GZipMiddleware: Compress if large? (Small response, probably not)
   └─→ Custom middleware: Log response status, add request ID to response header

10. HTTP response sent
    HTTP/1.1 201 Created
    Content-Type: application/json
    X-Request-ID: 550e8400-e29b-41d4-a716-446655440000
    
    {
      "user": {
        "id": "abc123def",
        "email": "newuser@example.com",
        "username": "newuser",
        "is_verified": false,
        "created_at": "2024-01-15T10:30:00Z"
      },
      "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMxMjNkZWYiLCJleHAiOjE3MDAwMDAwMDB9.signature...",
      "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMxMjNkZWYiLCJleHAiOjE3MDAwMDAwMDB9.signature...",
      "token_type": "bearer",
      "expires_in": 604800
    }

11. Client receives response
    ├─→ Parses JSON
    ├─→ Stores access_token (in memory or sessionStorage)
    ├─→ Stores refresh_token (in HttpOnly cookie)
    └─→ User is logged in!
    
    Subsequent requests:
    Authorization: Bearer eyJhbGc...
```

## Step-by-Step: Making an Authenticated API Request

```
1. Client has access token from login
   access_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJz..."

2. Client makes request with token
   GET /api/v1/scans HTTP/1.1
   Host: localhost:8000
   Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJz...

3. FastAPI processes through middleware & routing
   └─→ Matches: GET /api/v1/scans
   └─→ Calls: get_user_scans(
             current_user=Depends(get_current_user),
             db=Depends(get_db)
       )

4. Dependency: get_current_user
   (from app/core/security.py)
   
   a. Extract token from header
      auth_header = "Bearer eyJhbGc..."
      token = "eyJhbGc..."
   
   b. Verify token signature & validity
      payload = verify_token(token)
      └─→ Decodes: {sub: 'abc123def', exp: 1700000000, jti: 'xyz789', type: 'access'}
      └─→ Checks HMAC signature against SECRET_KEY
      └─→ Checks if token expired: exp > now? (Yes, valid)
      └─→ Checks if revoked: SELECT * FROM revoked_tokens WHERE jti='xyz789'
          Result: None (not revoked)
   
   c. Extract user ID
      user_id = payload.get("sub")  ← 'abc123def'
   
   d. Fetch user from database
      user = db.query(User).filter(User.id == 'abc123def').first()
      └─→ SQL: SELECT * FROM users WHERE id = 'abc123def' LIMIT 1
      └─→ Returns User object (if found) or None
   
   e. Check user is active
      if not user or not user.is_active:
          raise AuthenticationException("User not found or inactive")
   
   f. Return user object
      return user  ← Injected into handler as current_user

5. Handler execution: get_user_scans()
   
   Inside handler now has:
   - current_user: User object (id='abc123def')
   - db: Session (connection to database)
   
   Query scans for this user:
   scans = db.query(Scan).filter(
               Scan.user_id == current_user.id
           ).order_by(Scan.created_at.desc()).limit(10).all()
   
   └─→ SQL: SELECT * FROM owasp_scans
            WHERE user_id = 'abc123def'
            ORDER BY created_at DESC
            LIMIT 10

6. Database returns scan records
   Result: [Scan(id='scan-1', user_id='abc123def', target_url='https://', ...), ...]
   
   SQLAlchemy maps each row to Python object instance

7. Convert to response format
   response_scans = [
       ScanResponse.from_orm(scan) for scan in scans
   ]
   
   Each Scan ORM object → ScanResponse Pydantic model
   └─→ Serialization (Python objects → JSON-ready dicts)

8. Return response
   return {
       "scans": response_scans,
       "total": len(response_scans)
   }

9. HTTP response
   HTTP/1.1 200 OK
   Content-Type: application/json
   
   {
     "scans": [
       {
         "scan_id": "scan-1",
         "target_url": "https://example.com",
         "status": "completed",
         "created_at": "2024-01-15T09:00:00Z"
       },
       ...
     ],
     "total": 5
   }

10. Client receives list of their scans
    └─→ Only scans where user_id matches authenticated user
    └─→ Other users' scans never returned (enforced at DB query level)
```

## Step-by-Step: Creating a Scan (Data Write)

```
1. User initiates scan
   POST /api/v1/scans/comprehensive/start HTTP/1.1
   Authorization: Bearer eyJ...
   
   {
     "target_url": "https://vulnerable-app.example.com",
     "scan_types": ["owasp", "nuclei"],
     "options": {
       "enable_ai_analysis": true,
       "scan_mode": "standard"
     }
   }

2. Route: start_comprehensive_scan()
   
   Injected:
   - current_user (from token)
   - background_tasks (for async work)
   - db (database session)
   - request (HTTP request metadata)

3. Validate inputs
   ├─→ URL format valid? (Pydantic)
   ├─→ Scan types in allowed list?
   └─→ Options within constraints?

4. Create scan record in database
   
   scan_id = str(uuid.uuid4())  ← Generate unique ID
   
   scan_record = {
       "scan_id": scan_id,
       "user_id": current_user.id,
       "target_url": "https://vulnerable-app.example.com",
       "status": "pending",
       "progress": 0,
       "scan_types": ["owasp", "nuclei"],
       "options": {...},
       "created_at": now(),
       "started_at": None,  ← Will update when scan begins
       "completed_at": None
   }
   
   Insert via Supabase:
   result = supabase.admin.table("owasp_scans").insert(scan_record).execute()
   
   └─→ SQL: INSERT INTO owasp_scans 
            (scan_id, user_id, target_url, status, progress, scan_types, ...)
            VALUES (...)
   └─→ Database returns inserted record with timestamps

5. Check scan limits
   
   Query user's scan count:
   today_scans = supabase.admin.table("owasp_scans")\
       .select("count").eq("user_id", current_user.id)\
       .gte("created_at", today_start).execute()
   
   if today_scans >= MAX_SCANS_PER_USER_PER_DAY:
       Delete scan record we just created
       raise RateLimitException("Max scans per day exceeded")

6. Queue scan work
   
   background_tasks.add_task(
       run_comprehensive_scan,
       scan_id=scan_id,
       current_user_id=current_user.id,
       target_url="https://vulnerable-app.example.com",
       scan_types=["owasp", "nuclei"],
       options={...}
   )
   
   This schedules async work but returns immediately to client

7. Immediate response
   
   Return to client (before scan starts):
   HTTP/1.1 202 Accepted
   {
     "scan_id": "scan-uuid",
     "message": "Scan started successfully",
     "status_url": "/api/v1/scans/scan-uuid"
   }
   
   Client can now poll status_url to watch progress

8. Async background task: run_comprehensive_scan()
   
   (Runs in background thread, doesn't block response)
   
   a. Update scan status
      supabase.update_scan(scan_id, {"status": "running"})
      └─→ SQL: UPDATE owasp_scans SET status='running' WHERE scan_id='...'
   
   b. Initialize scanners
      ├─→ OWASP ZAP (via API at http://owasp-zap:8080)
      ├─→ Nuclei (Docker container or binary)
      └─→ Wapiti (Docker container or binary)
   
   c. Execute scan
      For each scanner:
      └─→ Send target URL
      └─→ Wait for results with timeout
      └─→ Collect findings
   
   d. Normalize results
      For each finding from each scanner:
      └─→ Map to common vulnerability schema
      └─→ Prepare for database storage
   
   e. Insert vulnerabilities
      vulns_to_insert = [
          {scan_id, title, severity, cvss_score, location, ...},
          {scan_id, title, severity, cvss_score, location, ...},
          ...
      ]
      
      result = supabase.insert_vulnerabilities(scan_id, vulns_to_insert)
      └─→ SQL: INSERT INTO owasp_vulnerabilities (scan_id, title, severity, ...)
               VALUES (...), (...), ...
      └─→ Batch insert for efficiency
   
   f. AI analysis (if enabled)
      ai_analysis = await llm_service.analyze_vulnerabilities(vulns)
      └─→ Call OpenAI/Groq LLM with vulnerability details
      └─→ Get back: remediations, impact analysis, etc.
      └─→ Store back in database
   
   g. Update final scan record
      supabase.update_scan(scan_id, {
          "status": "completed",
          "progress": 100,
          "completed_at": now(),
          "critical_count": 5,
          "high_count": 12,
          "medium_count": 24,
          "low_count": 45,
          "risk_score": 7.5,
          "ai_analysis": {...}
      })
      └─→ SQL: UPDATE owasp_scans SET status='completed', progress=100, ... WHERE scan_id='...'

9. WebSocket notification (optional)
   
   If WebSocket connection exists:
   └─→ Send message to client: {status: "completed", progress: 100}
   └─→ Client UI updates in real-time

10. Client polls status
    GET /api/v1/scans/{scan_id}
    
    Handler:
    ├─→ Verify user owns scan
    └─→ Query database for scan record
    └─→ Query database for vulnerabilities
    └─→ Return combined results
    
    Client sees:
    {
      "scan_id": "scan-uuid",
      "status": "completed",
      "vulnerabilities": [...],
      "risk_assessment": {...},
      "ai_analysis": [...]
    }
```

---

# Architecture Overview

## Complete System Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                         CLIENT LAYER                                 │
├──────────────────────────────────────────────────────────────────────┤
│  React Frontend (localhost:3000)                                     │
│  ├─ Auth Components (Sign Up, Login, Logout)                        │
│  ├─ Dashboard                                                        │
│  ├─ Scan Initiation Forms                                           │
│  ├─ Results Display                                                 │
│  └─ WebSocket listener (real-time updates)                          │
└──────────────────────────────────────────────────────────────────────┘
                              ↓ HTTPS
┌──────────────────────────────────────────────────────────────────────┐
│                    APPLICATION LAYER (FastAPI)                       │
├──────────────────────────────────────────────────────────────────────┤
│  Backend (localhost:8000)                                            │
│                                                                      │
│  ┌─ Middleware Stack ─────────────────────────────────────────┐    │
│  │ ├─ Security Headers (HSTS, CSP, etc.)                      │    │
│  │ ├─ CORS Validation                                         │    │
│  │ ├─ Injection Prevention                                    │    │
│  │ ├─ Rate Limiting                                           │    │
│  │ ├─ Request Logging                                         │    │
│  │ └─ Error Handling                                          │    │
│  └────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  ┌─ API Routes ──────────────────────────────────────────────┐    │
│  │ ├─ /auth (register, login, logout, refresh)               │    │
│  │ ├─ /scans (start, status, results, history)               │    │
│  │ ├─ /vulnerabilities (list, detail, filter)                │    │
│  │ ├─ /intelligence (threat intel, CVE, etc.)                │    │
│  │ ├─ /remediation (fix suggestions)                         │    │
│  │ ├─ /ws (WebSocket endpoint)                               │    │
│  │ └─ /health (status check)                                 │    │
│  └────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  ┌─ Services ────────────────────────────────────────────────┐    │
│  │ ├─ ComprehensiveScanner (orchestrates ZAP, Nuclei, Wapiti)│   │
│  │ ├─ LLMService (AI vulnerability analysis)                 │    │
│  │ ├─ ThreatIntelService (CVE, CVSS lookup)                  │    │
│  │ ├─ MITREService (ATT&CK mapping)                          │    │
│  │ └─ SecurityManager (JWT, passwords, encryption)           │    │
│  └────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────┘
                     ↓ SQLAlchemy   ↓ Direct SQL
┌──────────────────────────────────────────────────────────────────────┐
│                         ORM LAYER (SQLAlchemy)                       │
├──────────────────────────────────────────────────────────────────────┤
│  ┌─ Connection Pool ────────────────────────┐                       │
│  │ ├─ 10 active connections                 │                       │
│  │ ├─ Up to 20 overflow                     │                       │
│  │ └─ pool_pre_ping (health checks)         │                       │
│  └──────────────────────────────────────────┘                       │
│                                                                      │
│  ┌─ Session Management ─────────────────────┐                       │
│  │ ├─ Transaction context                   │                       │
│  │ ├─ Query builder                         │                       │
│  │ ├─ Change tracking                       │                       │
│  │ └─ Commit/rollback                       │                       │
│  └──────────────────────────────────────────┘                       │
│                                                                      │
│  ┌─ Models Mapping ─────────────────────────┐                       │
│  │ ├─ User → users table                    │                       │
│  │ ├─ Scan → owasp_scans table              │                       │
│  │ ├─ Vulnerability → owasp_vulnerabilities │                       │
│  │ ├─ Revocation → revoked_tokens           │                       │
│  │ └─ (Others) → various tables             │                       │
│  └──────────────────────────────────────────┘                       │
└──────────────────────────────────────────────────────────────────────┘
                     ↓ psycopg2 driver
┌──────────────────────────────────────────────────────────────────────┐
│                    DATABASE LAYER (PostgreSQL)                       │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Supabase PostgreSQL (AWS)                                          │
│  ├─ Host: aws-0-ap-south-1.pooler.supabase.com:6543                │
│  ├─ Database: postgres                                              │
│  ├─ User: postgres (with read/create/update/delete permissions)     │
│  │                                                                  │
│  ├─ Tables (Schema):                                                │
│  │  ├─ users (id PK, email UNIQUE, username UNIQUE, ...)          │
│  │  ├─ revoked_tokens (jti PK, expires_at)                        │
│  │  ├─ owasp_scans (scan_id PK, user_id FK, ...)                 │
│  │  ├─ owasp_vulnerabilities (id PK, scan_id FK, ...)            │
│  │  ├─ discovered_assets (id PK, scan_id FK, ...)                │
│  │  └─ (15+ more tables for threats, mitigations, etc.)            │
│  │                                                                  │
│  ├─ Indexes:                                                        │
│  │  ├─ users.email (for uniqueness & lookup)                      │
│  │  ├─ users.username (for uniqueness)                            │
│  │  ├─ owasp_scans.user_id (for filtering by user)               │
│  │  ├─ owasp_vulnerabilities.scan_id (for scan results)          │
│  │  └─ revoked_tokens.expires_at (for cleanup)                   │
│  │                                                                  │
│  └─ Transaction Isolation: READ COMMITTED (default)                │
│     └─ Dirty reads prevented, good balance                         │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│                    SCANNER LAYER (Docker Containers)                 │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ├─ OWASP ZAP (Port 8080)                                           │
│  │  ├─ Baseline scan (passive checks)                              │
│  │  ├─ Active scan (attack payloads)                               │
│  │  └─ API calls via zaproxy.py driver                             │
│  │                                                                  │
│  ├─ Nuclei (Docker container)                                      │
│  │  ├─ Template-based scanning                                     │
│  │  ├─ Mounted template library                                    │
│  │  └─ Subprocess execution via Docker                             │
│  │                                                                  │
│  ├─ Wapiti (Docker container)                                      │
│  │  ├─ Web app vulnerability scanner                               │
│  │  └─ Subprocess execution via Docker                             │
│  │                                                                  │
│  └─ Nikto (Docker container)                                       │
│     ├─ Web server fingerprinting                                   │
│     └─ Subprocess execution via Docker                             │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│                       CACHE LAYER (Redis)                            │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Redis (localhost:6379 in dev, cloud in prod)                       │
│  ├─ Session/token blacklist cache                                   │
│  ├─ User data cache (avoid repeated DB lookups)                     │
│  ├─ Scan status cache (in-memory fallback)                          │
│  ├─ Rate limit counting                                             │
│  └─ TTL (auto-expiration)                                           │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│                    AI/THREAT INTEL LAYER (External APIs)             │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ├─ OpenAI / Groq (LLM for analysis)                                │
│  ├─ VirusTotal (Malware analysis)                                   │
│  ├─ Google Safe Browsing (Phishing/malware detection)               │
│  ├─ AbuseIPDB (IP reputation)                                       │
│  ├─ NVD / Vulners (CVE information)                                 │
│  ├─ MITRE ATT&CK (Threat framework)                                 │
│  └─ SecurityTrails (Domain intelligence)                            │
└──────────────────────────────────────────────────────────────────────┘
```

## Data Flow: Request to Response

```
HTTP Request Arrives
    ↓
FastAPI Routing
    ↓ Match route, extract parameters
    ↓
Middleware Processing
    ├─ Security validation
    ├─ CORS checking
    ├─ Request logging
    └─ Injection prevention
    ↓
Dependency Injection
    ├─ parse body (Pydantic validation)
    ├─ extract auth token
    ├─ verify token with database
    ├─ get current user
    └─ get database session
    ↓
Route Handler Execution
    ├─ business logic
    ├─ query database (SQLAlchemy → SQL)
    │  ├─ database returns rows
    │  ├─ map to ORM objects
    │  └─ Python object access
    ├─ compute results
    ├─ optionally: write to database
    │  └─ INSERT/UPDATE/DELETE via SQLAlchemy
    └─ convert results to response models
    ↓
Response Serialization
    ├─ ORM objects → Pydantic models
    ├─ complex types → JSON primitives
    └─ timestamp conversion
    ↓
Response Middleware
    ├─ add security headers
    ├─ add correlation IDs
    └─ compression
    ↓
HTTP Response Sent to Client
```

## Key Components and Their Roles

### FastAPI Application
- **Role**: HTTP request router and handler
- **Responsibility**: 
  - Parse incoming requests
  - Validate inputs
  - Inject dependencies
  - Call route handlers
  - Serialize responses
- **Why separate**: Decouples HTTP protocol from business logic

### SQLAlchemy ORM
- **Role**: Bridge between Python and database
- **Responsibility**:
  - Convert Python objects to SQL
  - Convert SQL results to Python objects
  - Manage transactions
  - Handle connection pooling
- **Why separate**: Don't write raw SQL, type-safe operations

### Supabase PostgreSQL
- **Role**: Persistent data storage
- **Responsibility**:
  - ACID transactions
  - Data integrity (constraints, uniqueness)
  - Query execution
  - Backup/replication
- **Why separate**: Data lives beyond process lifetime

### SecurityManager
- **Role**: Cryptographic operations
- **Responsibility**:
  - Password hashing (bcrypt)
  - JWT token creation/verification
  - API key generation
  - Secure random generation
- **Why separate**: Centralize security logic, audit trail

### Supabase Client
- **Role**: Fallback and admin database operations
- **Responsibility**:
  - In-memory cache (when DB unavailable)
  - Service-role operations (bypass RLS)
  - Direct admin queries
  - Batch operations
- **Why separate**: Handle degradation gracefully

### Scanners (ZAP, Nuclei, Wapiti)
- **Role**: Security testing engines
- **Responsibility**:
  - Execute scans against targets
  - Generate findings
  - Format results
- **Why separate**: Parallel processing, resource isolation

## Data Consistency & Reliability

### ACID Transactions

Every database operation follows **ACID principles**:

**Atomicity**: All-or-nothing
```python
try:
    db.add(scan)
    db.add(vulnerability)
    db.commit()  # Both succeed or both rollback
except:
    db.rollback()  # Neither inserted
```

**Consistency**: Data remains valid
```python
# Database constraints:
# - user_id is NOT NULL
# - user_id REFERENCES users(id)
# Can't insert scan without valid user
```

**Isolation**: Concurrent requests don't see partial changes
```python
# Request 1 inserts scan, not committed yet
# Request 2 can't see Request 1's scan
# Once committed: visible to all
```

**Durability**: Committed data survives crashes
```python
# db.commit() → Postgres writes to disk
# Even if server dies, data persists
```

### Fallback System (Degraded Mode)

When database unavailable:

```python
def create_scan(self, record: Dict) -> Optional[Dict]:
    try:
        res = self.admin.table("owasp_scans").insert(record).execute()
        self._memory_scans[record["scan_id"]] = res.data[0]
        return res.data[0]
    except Exception as e:
        logger.warning(f"DB failed: {e}, using memory fallback")
        self._memory_scans[record["scan_id"]] = record  # In-memory backup
        return record
```

**Trade-off**: 
- Availability: Can continue operating
- Consistency: Data temporarily in memory only
- Data eventually synced to DB when it comes back

### Error Handling

```python
@app.exception_handler(LinkLoadException)
async def linkload_exception_handler(request: Request, exc: LinkLoadException):
    """Handle all LinkLoad exceptions with proper logging"""
    logger.error(f"LinkLoad exception: {exc}", exc_info=True)
    
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.error_code,
            "detail": exc.detail
        }
    )

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch unhandled exceptions"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    
    # Don't leak internal details in production
    detail = "An unexpected error occurred"
    if settings.ENVIRONMENT == "development":
        detail = str(exc)
    
    return JSONResponse(
        status_code=500,
        content={"error": "InternalServerError", "detail": detail}
    )
```

---

## Summary

The LinkLoad database architecture is a **multi-layered system** designed for:

1. **Security**: Encryption, hashing, token revocation, role-based access
2. **Scalability**: Connection pooling, indexing, batch operations
3. **Reliability**: ACID transactions, fallback systems, error handling
4. **Maintainability**: ORM abstraction, dependency injection, clear separation

Every request follows the same pattern:
- **Authenticate** via JWT token
- **Authorize** via user ownership checks
- **Query** database via SQLAlchemy ORM
- **Process** results in Python code
- **Return** JSON response

The database is the system's **source of truth**—without it, users would lose their scan history, authentication state, and security findings. That's why every operation is carefully designed with transactions, validation, and error handling.
