-- ========================================
-- USERS & AUTHENTICATION
-- ========================================
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT CHECK (role IN ('admin', 'manager', 'team_lead', 'editor', 'viewer')) NOT NULL,
    org TEXT,  -- ✅ Added missing comma
    email TEXT,  -- ✅ Added missing comma
    last_login TIMESTAMP,
    account_locked BOOL DEFAULT false NOT NULL,  -- ✅ Added missing comma
    created_at TIMESTAMP DEFAULT now(),  -- ✅ Added missing comma
    updated_at TIMESTAMP DEFAULT now(),  -- ✅ Added missing comma
    deleted_at TIMESTAMP
);

-- User Login History
CREATE TABLE user_logins (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE CASCADE NOT NULL,
    login_time TIMESTAMP DEFAULT now() NOT NULL,
    ip_address TEXT,
    user_agent TEXT
);

-- ========================================
-- TEAMS & ROLE-BASED ACCESS
-- ========================================

CREATE TABLE teams (
    id SERIAL PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT now()
);

-- Team Memberships with Specific Roles
CREATE TABLE team_members (
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    team_id INT REFERENCES teams(id) ON DELETE CASCADE,
    role TEXT CHECK (role IN ('manager', 'team_lead', 'member', "editor")) NOT NULL,
    PRIMARY KEY (user_id, team_id)
);

-- ========================================
-- CONTRACTS & FINANCIAL TRACKING
-- ========================================

CREATE TABLE contracts (
    id SERIAL PRIMARY KEY,
    number VARCHAR(50) NOT NULL UNIQUE,
    name TEXT NOT NULL,
    awarding_agency TEXT,
    award_date DATE NOT NULL,
    start_date DATE,
    end_date DATE,
    modification_date DATE,
    modification_count INT DEFAULT 0,
    latest_modification_number VARCHAR(50),
    latest_modification_reason TEXT,
    current_obligation DOUBLE PRECISION,
    current_spend DOUBLE PRECISION,
    spend_ceiling DOUBLE PRECISION,
    base_value DOUBLE PRECISION,
    funding_source TEXT,
    status TEXT NOT NULL,
    pop_start_date DATE,
    pop_end_date DATE,
    option_years INT,
    reporting_frequency TEXT,
    last_report_date DATE,
    prime_contractor TEXT,
    contract_type TEXT,
    invoice_count INT DEFAULT 0,
    classification TEXT NOT NULL DEFAULT 'Unclassified',
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP DEFAULT now()
);

-- Contract Modifications

CREATE TABLE contract_modifications (
    id SERIAL PRIMARY KEY,
    contract_id INT REFERENCES contracts(id) ON DELETE CASCADE NOT NULL,
    modification_number VARCHAR(50) NOT NULL UNIQUE, -- Unique identifier for modifications
    modification_date DATE NOT NULL,
    modification_type TEXT NOT NULL, -- 'funding', 'schedule', 'scope', 'admin'
    modification_reason TEXT NOT NULL, 
    previous_value DOUBLE PRECISION, -- Previous contract value before modification
    modification_value DOUBLE PRECISION NOT NULL, -- New contract value after modification
    new_end_date DATE, -- If the modification extends the contract
    justification TEXT, -- Explanation for modification
    modification_document TEXT, -- Link to supporting document
    modified_by TEXT NOT NULL, -- User who made the modification
    classification TEXT NOT NULL DEFAULT 'Unclassified',
    created_at TIMESTAMP DEFAULT now()
);

-- Contract Invoices
CREATE TABLE contract_invoices (
    id SERIAL PRIMARY KEY,
    contract_id INT REFERENCES contracts(id) ON DELETE CASCADE NOT NULL,
    invoice_number VARCHAR(50) NOT NULL UNIQUE,
    invoice_date DATE NOT NULL,
    invoice_amount DOUBLE PRECISION NOT NULL,
    payment_status TEXT CHECK (payment_status IN ('Paid', 'Pending', 'Overdue')) NOT NULL,
    classification TEXT NOT NULL DEFAULT 'Unclassified',
    created_at TIMESTAMP DEFAULT now()
);

-- ========================================
-- TASK ORDERS
-- ========================================

CREATE TABLE taskorders (
    id SERIAL PRIMARY KEY,
    contract_id INT REFERENCES contracts(id) ON DELETE RESTRICT NOT NULL,
    name TEXT UNIQUE NOT NULL,
    producer TEXT,
    cor TEXT,
    pop DATERANGE,
    price DOUBLE PRECISION CHECK (price >= 0),
    status TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT now()
);

-- ========================================
-- PRODUCTS & PRODUCT TYPES
-- ========================================

CREATE TABLE product_types (
    id SERIAL PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    acronym TEXT UNIQUE NOT NULL
);

CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    taskorder_id INT REFERENCES taskorders(id) ON DELETE SET NULL, 
    item_id VARCHAR(100) NOT NULL,
    site_id VARCHAR(50) NOT NULL,
    product_type_id INT REFERENCES product_types(id) NOT NULL, 
    status VARCHAR(50) NOT NULL,
    status_date DATE DEFAULT CURRENT_DATE NOT NULL,
    acceptance_date DATE,
    publish_date DATE,
    file_path TEXT,
    s2_index VARCHAR(24),
    geom GEOMETRY NOT NULL, -- PostGIS Geometry
    classification TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT now() NOT NULL
);

-- ========================================
-- REVIEWS
-- ========================================

CREATE TABLE reviews (
    id SERIAL PRIMARY KEY,
    product_id INT REFERENCES products(id) ON DELETE CASCADE NOT NULL,
    reviewer_id INT REFERENCES users(id) ON DELETE RESTRICT NOT NULL,
    review_status TEXT CHECK (review_status IN ('Draft','Pending','Approved','Sent')) NOT NULL DEFAULT 'Pending',
    product_status TEXT CHECK (product_status IN ('In Review', 'Accepted', 'Rejected')) NOT NULL,
    review_path TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT now() NOT NULL,
    updated_at TIMESTAMP DEFAULT now() NOT NULL
);

-- ========================================
-- DOCUMENT MANAGEMENT
-- ========================================

CREATE TABLE documents (
    id SERIAL PRIMARY KEY,
    contract_id INT REFERENCES contracts(id) ON DELETE CASCADE,
    taskorder_id INT REFERENCES taskorders(id) ON DELETE CASCADE,
    product_id INT REFERENCES products(id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT now()
);

-- ========================================
-- TEAM-BASED PRODUCT ACCESS CONTROL
-- ========================================


CREATE TABLE explicit_team_product (
    product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT CHECK (role IN ('team_lead', 'editor', 'member', 'viewer')) NOT NULL,
    PRIMARY KEY (product_id, user_id)
);

CREATE INDEX idx_explicit_team_product_product_id ON explicit_team_product (product_id);
CREATE INDEX idx_explicit_team_product_user_id ON explicit_team_product (user_id);

CREATE TABLE product_type_teams (
    product_type_id INTEGER NOT NULL REFERENCES product_types(id) ON DELETE CASCADE,
    team_id INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    PRIMARY KEY (product_type_id, team_id)
);

CREATE INDEX idx_product_type_teams_product_type_id ON product_type_teams (product_type_id);
CREATE INDEX idx_product_type_teams_team_id ON product_type_teams (team_id);

-- ========================================
-- PERFORMANCE & INDEXING
-- ========================================

-- Spatial Index for Geospatial Queries
CREATE INDEX idx_products_geom ON products USING GIST (geom);
CREATE TABLE task_order_teams (
    task_order_id INTEGER NOT NULL REFERENCES taskorders(id) ON DELETE CASCADE,
    team_id INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    PRIMARY KEY (task_order_id, team_id)
);

CREATE INDEX idx_task_order_teams_task_order_id ON task_order_teams (task_order_id);
CREATE INDEX idx_task_order_teams_team_id ON task_order_teams (team_id);

CREATE TYPE approval_request_type AS ENUM (
  'team_join',
  'product_access',
  'product_review_approval',
  'product_checkout'
);

CREATE TYPE approval_status AS ENUM (
  'pending',
  'approved',
  'rejected'
);

CREATE TABLE approval_requests (
  id SERIAL PRIMARY KEY,
  request_type approval_request_type NOT NULL,
  requested_by INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target_id INTEGER,  -- This refers to the team/product/review based on request_type
  details JSONB,      -- Additional metadata (role, justification, etc.)
  status approval_status DEFAULT 'pending',
  reviewed_by INTEGER REFERENCES users(id),
  requested_at TIMESTAMP DEFAULT now(),
  reviewed_at TIMESTAMP
);

