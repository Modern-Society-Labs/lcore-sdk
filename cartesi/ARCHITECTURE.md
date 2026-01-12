# Cartesi SQLite Framework Architecture

## Overview

This document provides a comprehensive guide to the Cartesi SQLite-based rollup data layer architecture. Originally designed for a lending platform with Plaid integration, this framework can be generalized to handle data ingestion from **any external data source** and expose query endpoints for that data.

The architecture is built on three core principles:
1. **Deterministic State** - All state changes happen through verifiable transactions
2. **Data Source Agnostic** - The pattern works for any external API (Plaid, Stripe, Shopify, etc.)
3. **Proof-Ready** - Built-in support for zkProofs and data verification

---

## Table of Contents

1. [System Architecture](#system-architecture)
2. [File Structure & Responsibilities](#file-structure--responsibilities)
3. [Core Components Deep Dive](#core-components-deep-dive)
4. [Data Flow Patterns](#data-flow-patterns)
5. [How Files Work Together](#how-files-work-together)
6. [Generalizing for Multiple Data Sources](#generalizing-for-multiple-data-sources)
7. [Adding a New Data Source (Step-by-Step)](#adding-a-new-data-source-step-by-step)
8. [API Reference](#api-reference)
9. [Best Practices](#best-practices)

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           EXTERNAL WORLD                                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐      │
│  │  Plaid   │  │  Stripe  │  │ Shopify  │  │  Custom  │  │  Any API │      │
│  │   API    │  │   API    │  │   API    │  │   API    │  │          │      │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘      │
│       │             │             │             │             │             │
│       └─────────────┴─────────────┴─────────────┴─────────────┘             │
│                                   │                                          │
│                    ┌──────────────▼──────────────┐                          │
│                    │     Backend / Middleware     │                          │
│                    │   (Fetches & Signs Data)     │                          │
│                    └──────────────┬──────────────┘                          │
│                                   │                                          │
└───────────────────────────────────┼──────────────────────────────────────────┘
                                    │
                    ┌───────────────▼───────────────┐
                    │      Cartesi Rollup Layer     │
                    │  ┌─────────────────────────┐  │
                    │  │        index.ts         │  │  ← Entry Point
                    │  │   (Main Event Loop)     │  │
                    │  └───────────┬─────────────┘  │
                    │              │                │
                    │  ┌───────────▼─────────────┐  │
                    │  │       router.ts         │  │  ← Request Router
                    │  │  (Advance/Inspect)      │  │
                    │  └───────────┬─────────────┘  │
                    │              │                │
                    │  ┌───────────▼─────────────┐  │
                    │  │       handlers/         │  │  ← Business Logic
                    │  │  (Domain Handlers)      │  │
                    │  └───────────┬─────────────┘  │
                    │              │                │
                    │  ┌───────────▼─────────────┐  │
                    │  │         db.ts           │  │  ← Data Access Layer
                    │  │   (SQLite via sql.js)   │  │
                    │  └───────────┬─────────────┘  │
                    │              │                │
                    │  ┌───────────▼─────────────┐  │
                    │  │    SQLite Database      │  │  ← In-Memory State
                    │  │   (WebAssembly)         │  │
                    │  └─────────────────────────┘  │
                    │                               │
                    └───────────────────────────────┘
```

---

## File Structure & Responsibilities

```
cartesi-sqlite-framework/
├── src/
│   ├── index.ts              # Application entry point & main loop
│   ├── router.ts             # Request routing & authorization
│   ├── db.ts                 # Database schema & CRUD operations
│   ├── config.ts             # Environment configuration
│   │
│   ├── handlers/             # Domain-specific business logic
│   │   ├── index.ts          # Handler exports aggregator
│   │   ├── entity.ts         # Primary entity handlers (users, accounts)
│   │   ├── data-source.ts    # External data ingestion handlers
│   │   ├── computation.ts    # Derived calculations handlers
│   │   ├── proof.ts          # Data proof verification handlers
│   │   └── stats.ts          # Aggregation & statistics handlers
│   │
│   └── utils/                # Shared utilities
│       ├── calculations.ts   # Domain-specific calculations
│       └── validation.ts     # Input validation helpers
│
├── package.json              # Dependencies
├── tsconfig.json             # TypeScript configuration
└── ARCHITECTURE.md           # This document
```

### File Responsibilities

| File | Purpose | Key Exports |
|------|---------|-------------|
| **index.ts** | Entry point. Initializes DB, creates router, runs main event loop | `main()` |
| **router.ts** | Routes advance/inspect requests to handlers. Handles authorization, payload parsing | `Router`, `createRouter()`, `RouteConfig` |
| **db.ts** | SQLite schema, initialization, all CRUD operations | `initDatabase()`, `getDatabase()`, entity operations |
| **config.ts** | Environment variable configuration with defaults | Configuration getter functions |
| **handlers/*.ts** | Business logic for each domain area | Handler functions for advance/inspect |

---

## Core Components Deep Dive

### 1. Database Layer (`db.ts`)

The database layer uses **sql.js** (SQLite compiled to WebAssembly) for deterministic in-rollup persistence.

#### Key Patterns:

```typescript
// Singleton pattern for database instance
let db: Database | null = null;

export async function initDatabase(): Promise<Database> {
  if (db) return db;

  const SQL = await initSqlJs();
  db = new SQL.Database();

  // Create schema
  db.run(`CREATE TABLE IF NOT EXISTS ...`);

  return db;
}

export function getDatabase(): Database {
  if (!db) throw new Error('Database not initialized');
  return db;
}
```

#### Helper Functions for Type-Safe Queries:

```typescript
// Extract first result set
function getFirstResult(result: QueryExecResult[]): QueryExecResult | undefined {
  return result[0];
}

// Extract rows from result
function getRows(result: QueryExecResult | undefined): SqlRow[] {
  return result?.values ?? [];
}

// Extract scalar value with default
function getScalar<T>(result: QueryExecResult[], defaultValue: T): T {
  const firstRow = getFirstResult(result)?.values[0];
  return firstRow?.[0] !== undefined ? firstRow[0] as T : defaultValue;
}
```

#### CRUD Pattern:

```typescript
// CREATE with upsert
export function createEntity(data: EntityInput): Entity {
  const database = getDatabase();
  database.run(
    `INSERT INTO entities (...) VALUES (?, ?, ?)
     ON CONFLICT(unique_field) DO UPDATE SET ...`,
    [data.field1, data.field2, new Date().toISOString()]
  );
  return getEntityById(data.id)!;
}

// READ with type mapping
export function getEntityById(id: string): Entity | null {
  const database = getDatabase();
  const result = database.exec(`SELECT ... FROM entities WHERE id = ?`, [id]);

  const row = getFirstResult(result)?.values[0];
  if (!row) return null;

  return {
    id: row[0] as string,
    field1: row[1] as string,
    // ... map all fields
  };
}

// UPDATE
export function updateEntity(id: string, updates: Partial<Entity>): void {
  const database = getDatabase();
  database.run(
    `UPDATE entities SET field1 = ?, updated_at = ? WHERE id = ?`,
    [updates.field1, new Date().toISOString(), id]
  );
}
```

---

### 2. Router Layer (`router.ts`)

The router handles two types of requests:

- **Advance Requests**: State-changing operations (INSERT, UPDATE, DELETE)
- **Inspect Requests**: Read-only queries (SELECT)

#### Router Structure:

```typescript
export interface RouteConfig {
  advance: Record<string, AdvanceHandler>;
  inspect: Record<string, InspectHandler>;
}

export type AdvanceHandler = (
  data: AdvanceRequestData,
  payload: unknown
) => Promise<{ status: RequestHandlerResult; response?: unknown }>;

export type InspectHandler = (query: InspectQuery) => Promise<unknown>;

export class Router {
  private advanceHandlers: Map<string, AdvanceHandler> = new Map();
  private inspectHandlers: Map<string, InspectHandler> = new Map();

  async handleAdvance(data: AdvanceRequestData): Promise<RequestHandlerResult> {
    // 1. Check authorization
    // 2. Decode & validate payload
    // 3. Route to appropriate handler
    // 4. Send notice/report
  }

  async handleInspect(data: InspectRequestData): Promise<void> {
    // 1. Parse query
    // 2. Route to handler
    // 3. Send report with result
  }
}
```

#### Authorization Pattern:

```typescript
const AUTHORIZED_SUBMITTERS = new Set<string>(
  (process.env.AUTHORIZED_SENDERS || '')
    .split(',')
    .map(addr => addr.trim().toLowerCase())
    .filter(Boolean)
);

export function isAuthorizedSender(sender: string): boolean {
  // Empty whitelist = development mode (allow all)
  if (AUTHORIZED_SUBMITTERS.size === 0) return true;
  return AUTHORIZED_SUBMITTERS.has(sender.toLowerCase());
}
```

---

### 3. Handler Layer (`handlers/*.ts`)

Handlers contain business logic for specific domains. Each handler follows a consistent pattern:

#### Advance Handler Pattern:

```typescript
interface CreateEntityPayload {
  action: 'create_entity';
  field1: string;
  field2: number;
}

export const handleCreateEntity: AdvanceHandler = async (
  data: AdvanceRequestData,
  payload: unknown
) => {
  const { field1, field2 } = payload as CreateEntityPayload;

  // 1. Validate input
  if (!field1 || typeof field1 !== 'string') {
    throw new Error('Valid field1 is required');
  }

  // 2. Check business rules
  const existing = getEntityByField(field1);
  if (existing) {
    throw new Error('Entity already exists');
  }

  // 3. Perform operation
  const entity = createEntity({ field1, field2 });

  // 4. Return response
  return {
    status: 'accept',
    response: {
      action: 'create_entity',
      success: true,
      entity: sanitizeEntity(entity),
    },
  };
};
```

#### Inspect Handler Pattern:

```typescript
export const handleInspectEntity: InspectHandler = async (query: InspectQuery) => {
  const { params } = query;

  // Handle different query variations
  if (params.id) {
    const entity = getEntityById(params.id);
    if (!entity) return { error: 'Entity not found' };
    return { entity: sanitizeEntity(entity) };
  }

  if (params.filter) {
    const entities = getEntitiesByFilter(params.filter);
    return { entities: entities.map(sanitizeEntity) };
  }

  return { error: 'ID or filter parameter required' };
};
```

---

### 4. Entry Point (`index.ts`)

The entry point initializes the system and runs the main event loop:

```typescript
const routeConfig: RouteConfig = {
  advance: {
    create_entity: handleCreateEntity,
    update_entity: handleUpdateEntity,
    sync_data: handleSyncData,
    // ... more handlers
  },
  inspect: {
    entity: handleInspectEntity,
    data: handleInspectData,
    stats: handleInspectStats,
    // ... more handlers
  },
};

const main = async () => {
  // Initialize database
  await initDatabase();

  // Create router with all handlers
  const router = createRouter(routeConfig);

  // Main event loop
  while (true) {
    const { response } = await POST('/finish', { body: { status } });

    if (response.status === 200) {
      const data = await response.json();

      switch (data.request_type) {
        case 'advance_state':
          status = await router.handleAdvance(data.data);
          break;
        case 'inspect_state':
          await router.handleInspect(data.data);
          status = 'accept';
          break;
      }
    }
  }
};

main().catch(e => process.exit(1));
```

---

## Data Flow Patterns

### Pattern 1: External Data Ingestion (e.g., Plaid Transactions)

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   External   │     │   Backend    │     │   Cartesi    │
│     API      │     │  Middleware  │     │   Rollup     │
└──────┬───────┘     └──────┬───────┘     └──────┬───────┘
       │                    │                    │
       │  1. Fetch Data     │                    │
       │<───────────────────│                    │
       │                    │                    │
       │  2. Return Data    │                    │
       │───────────────────>│                    │
       │                    │                    │
       │                    │  3. Sign & Submit  │
       │                    │───────────────────>│
       │                    │                    │
       │                    │                    │  4. Validate
       │                    │                    │  5. Store in SQLite
       │                    │                    │  6. Emit Notice
       │                    │                    │
       │                    │  7. Acknowledge    │
       │                    │<───────────────────│
       │                    │                    │
```

**Implementation:**

```typescript
// Handler for syncing external data
export const handleSyncData: AdvanceHandler = async (data, payload) => {
  const { entity_id, records, cursor } = payload as SyncDataPayload;

  // Validate
  if (!Array.isArray(records)) throw new Error('Records must be array');
  if (records.length > MAX_RECORDS_PER_SYNC) throw new Error('Too many records');

  // Get or create parent entity
  let entity = getEntityById(entity_id);
  if (!entity) entity = createEntity({ id: entity_id });

  // Insert records (with upsert for idempotency)
  const insertedCount = insertRecords(entity.id, records);

  // Update sync cursor for incremental sync
  if (cursor) updateSyncCursor(entity.id, cursor);

  return {
    status: 'accept',
    response: { action: 'sync_data', records_synced: insertedCount },
  };
};
```

---

### Pattern 2: Derived Computations (e.g., DSCR Calculation)

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Client     │     │   Cartesi    │     │   Database   │
│              │     │   Handler    │     │   (SQLite)   │
└──────┬───────┘     └──────┬───────┘     └──────┬───────┘
       │                    │                    │
       │  1. Request Calc   │                    │
       │───────────────────>│                    │
       │                    │                    │
       │                    │  2. Fetch Data     │
       │                    │───────────────────>│
       │                    │                    │
       │                    │  3. Return Data    │
       │                    │<───────────────────│
       │                    │                    │
       │                    │  4. Compute Result │
       │                    │                    │
       │                    │  5. Store Result   │
       │                    │───────────────────>│
       │                    │                    │
       │  6. Return Result  │                    │
       │<───────────────────│                    │
       │                    │                    │
```

**Implementation:**

```typescript
export const handleCompute: AdvanceHandler = async (data, payload) => {
  const { entity_id, params } = payload as ComputePayload;

  // 1. Fetch required data
  const entity = getEntityById(entity_id);
  if (!entity) throw new Error('Entity not found');

  const records = getRecordsForComputation(entity.id);
  if (records.length === 0) throw new Error('No data for computation');

  // 2. Perform computation
  const result = performCalculation(records, params);

  // 3. Store result with input hash for verification
  const inputHash = hashInputs(records);
  saveComputationResult(entity_id, result, inputHash);

  // 4. Update entity status
  updateEntityStatus(entity_id, result.meetsThreshold ? 'approved' : 'pending');

  return {
    status: 'accept',
    response: { action: 'compute', result, input_hash: inputHash },
  };
};
```

---

### Pattern 3: Proof Verification

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Prover     │     │   Cartesi    │     │   Database   │
│  (Backend)   │     │   Handler    │     │   (SQLite)   │
└──────┬───────┘     └──────┬───────┘     └──────┬───────┘
       │                    │                    │
       │  1. Submit Proof   │                    │
       │───────────────────>│                    │
       │                    │                    │
       │                    │  2. Verify Sig     │
       │                    │                    │
       │                    │  3. Check Expiry   │
       │                    │                    │
       │                    │  4. Store Proof    │
       │                    │───────────────────>│
       │                    │                    │
       │                    │  5. Mark Verified  │
       │                    │───────────────────>│
       │                    │                    │
       │  6. Confirmation   │                    │
       │<───────────────────│                    │
       │                    │                    │
```

---

## How Files Work Together

### Request Lifecycle (Advance)

```
1. index.ts receives advance request
   │
   ▼
2. router.ts.handleAdvance()
   ├── Checks authorization (isAuthorizedSender)
   ├── Decodes hex payload to JSON
   ├── Validates payload structure
   ├── Routes to handler based on "action" field
   │
   ▼
3. handlers/entity.ts.handleCreateEntity()
   ├── Validates specific fields
   ├── Calls db.ts functions
   │
   ▼
4. db.ts.createEntity()
   ├── Executes SQL
   ├── Returns typed result
   │
   ▼
5. Handler returns { status, response }
   │
   ▼
6. router.ts sends notice/report to rollup server
```

### Request Lifecycle (Inspect)

```
1. index.ts receives inspect request
   │
   ▼
2. router.ts.handleInspect()
   ├── Decodes payload
   ├── Parses query (JSON or path format)
   ├── Routes to handler based on query type
   │
   ▼
3. handlers/entity.ts.handleInspectEntity()
   ├── Calls db.ts functions
   ├── Sanitizes response
   │
   ▼
4. db.ts.getEntityById()
   ├── Executes SQL
   ├── Maps result to typed object
   │
   ▼
5. router.ts sends report with JSON result
```

---

## Generalizing for Multiple Data Sources

The current architecture can be extended to handle any external data source. Here's the pattern:

### Generic Data Source Schema

```sql
-- Core entity table (users, accounts, etc.)
CREATE TABLE IF NOT EXISTS entities (
  id TEXT PRIMARY KEY,
  external_id TEXT UNIQUE,
  entity_type TEXT NOT NULL,
  metadata TEXT, -- JSON for flexible fields
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Generic data records from any source
CREATE TABLE IF NOT EXISTS data_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  entity_id TEXT NOT NULL,
  source_type TEXT NOT NULL,        -- 'plaid', 'stripe', 'shopify', etc.
  source_record_id TEXT,            -- External ID for deduplication
  record_type TEXT NOT NULL,        -- 'transaction', 'order', 'event', etc.
  amount INTEGER,                   -- Normalized to smallest unit
  timestamp TEXT NOT NULL,
  metadata TEXT,                    -- JSON for source-specific fields
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(source_type, source_record_id),
  FOREIGN KEY (entity_id) REFERENCES entities(id)
);

-- Sync state for incremental updates
CREATE TABLE IF NOT EXISTS sync_state (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  entity_id TEXT NOT NULL,
  source_type TEXT NOT NULL,
  cursor TEXT,
  last_sync_at TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(entity_id, source_type),
  FOREIGN KEY (entity_id) REFERENCES entities(id)
);

-- Computed results
CREATE TABLE IF NOT EXISTS computations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  entity_id TEXT NOT NULL,
  computation_type TEXT NOT NULL,
  result_value REAL,
  input_hash TEXT,
  computed_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (entity_id) REFERENCES entities(id)
);

-- Data proofs for verification
CREATE TABLE IF NOT EXISTS proofs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  proof_id TEXT UNIQUE NOT NULL,
  entity_id TEXT NOT NULL,
  source_type TEXT NOT NULL,
  data_hash TEXT NOT NULL,
  signature TEXT NOT NULL,
  verified INTEGER DEFAULT 0,
  expires_at TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (entity_id) REFERENCES entities(id)
);
```

### Source-Agnostic Handler Pattern

```typescript
interface SyncDataPayload {
  action: 'sync_data';
  entity_id: string;
  source_type: 'plaid' | 'stripe' | 'shopify' | 'custom';
  records: DataRecordInput[];
  cursor?: string;
}

interface DataRecordInput {
  source_record_id?: string;
  record_type: string;
  amount?: number;
  timestamp: string;
  metadata?: Record<string, unknown>;
}

export const handleSyncData: AdvanceHandler = async (data, payload) => {
  const { entity_id, source_type, records, cursor } = payload as SyncDataPayload;

  // Validate based on source type
  const validator = getValidatorForSource(source_type);
  const validatedRecords = validator.validateRecords(records);

  // Transform to normalized format
  const transformer = getTransformerForSource(source_type);
  const normalizedRecords = transformer.transform(validatedRecords);

  // Insert with source-aware deduplication
  const insertedCount = insertDataRecords(entity_id, source_type, normalizedRecords);

  // Update cursor
  if (cursor) updateSyncCursor(entity_id, source_type, cursor);

  return {
    status: 'accept',
    response: {
      action: 'sync_data',
      source_type,
      records_synced: insertedCount,
    },
  };
};
```

---

## Adding a New Data Source (Step-by-Step)

### Example: Adding Stripe Payment Data

#### Step 1: Define Schema Extension (db.ts)

```typescript
// Add to initDatabase()
db.run(`
  CREATE TABLE IF NOT EXISTS stripe_payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id TEXT NOT NULL,
    stripe_payment_id TEXT UNIQUE,
    amount INTEGER NOT NULL,
    currency TEXT DEFAULT 'usd',
    status TEXT,
    payment_method TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (entity_id) REFERENCES entities(id)
  );

  CREATE INDEX IF NOT EXISTS idx_stripe_entity ON stripe_payments(entity_id);
  CREATE INDEX IF NOT EXISTS idx_stripe_status ON stripe_payments(status);
`);
```

#### Step 2: Define Types & CRUD (db.ts)

```typescript
export interface StripePayment {
  id: number;
  entity_id: string;
  stripe_payment_id: string | null;
  amount: number;
  currency: string;
  status: string | null;
  payment_method: string | null;
  created_at: string;
}

export interface StripePaymentInput {
  stripe_payment_id?: string;
  amount: number;
  currency?: string;
  status?: string;
  payment_method?: string;
}

export function insertStripePayments(
  entityId: string,
  payments: StripePaymentInput[]
): number {
  const database = getDatabase();
  let insertedCount = 0;

  for (const payment of payments) {
    try {
      database.run(
        `INSERT INTO stripe_payments
         (entity_id, stripe_payment_id, amount, currency, status, payment_method)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(stripe_payment_id) DO UPDATE SET
           amount = excluded.amount,
           status = excluded.status`,
        [
          entityId,
          payment.stripe_payment_id || null,
          payment.amount,
          payment.currency || 'usd',
          payment.status || null,
          payment.payment_method || null,
        ]
      );
      insertedCount++;
    } catch (error) {
      console.error(`Failed to insert Stripe payment: ${error}`);
    }
  }

  return insertedCount;
}

export function getStripePaymentsByEntity(entityId: string): StripePayment[] {
  const database = getDatabase();
  const result = database.exec(
    `SELECT id, entity_id, stripe_payment_id, amount, currency, status, payment_method, created_at
     FROM stripe_payments WHERE entity_id = ? ORDER BY created_at DESC`,
    [entityId]
  );

  const firstResult = result[0];
  if (!firstResult) return [];

  return firstResult.values.map(row => ({
    id: row[0] as number,
    entity_id: row[1] as string,
    stripe_payment_id: row[2] as string | null,
    amount: row[3] as number,
    currency: row[4] as string,
    status: row[5] as string | null,
    payment_method: row[6] as string | null,
    created_at: row[7] as string,
  }));
}
```

#### Step 3: Create Handler (handlers/stripe.ts)

```typescript
import { AdvanceHandler, InspectHandler, InspectQuery, AdvanceRequestData } from '../router';
import {
  insertStripePayments,
  getStripePaymentsByEntity,
  getEntityById,
  createEntity,
  StripePaymentInput,
} from '../db';

interface SyncStripePaymentsPayload {
  action: 'sync_stripe_payments';
  entity_id: string;
  payments: StripePaymentInput[];
}

const MAX_PAYMENTS_PER_SYNC = 500;

export const handleSyncStripePayments: AdvanceHandler = async (
  data: AdvanceRequestData,
  payload: unknown
) => {
  const { entity_id, payments } = payload as SyncStripePaymentsPayload;

  // Validate
  if (!entity_id) throw new Error('entity_id is required');
  if (!Array.isArray(payments)) throw new Error('payments must be array');
  if (payments.length > MAX_PAYMENTS_PER_SYNC) {
    throw new Error(`Maximum ${MAX_PAYMENTS_PER_SYNC} payments per sync`);
  }

  // Validate each payment
  for (let i = 0; i < payments.length; i++) {
    const p = payments[i];
    if (typeof p?.amount !== 'number') {
      throw new Error(`Payment ${i}: invalid amount`);
    }
  }

  // Get or create entity
  let entity = getEntityById(entity_id);
  if (!entity) entity = createEntity({ id: entity_id });

  // Insert payments
  const insertedCount = insertStripePayments(entity.id, payments);

  return {
    status: 'accept',
    response: {
      action: 'sync_stripe_payments',
      success: true,
      entity_id,
      payments_synced: insertedCount,
    },
  };
};

export const handleInspectStripePayments: InspectHandler = async (
  query: InspectQuery
) => {
  const { params } = query;

  if (!params.entity_id) {
    return { error: 'entity_id parameter required' };
  }

  const payments = getStripePaymentsByEntity(params.entity_id);

  return {
    entity_id: params.entity_id,
    payment_count: payments.length,
    payments: payments.slice(0, 100), // Limit response size
    total_amount: payments.reduce((sum, p) => sum + p.amount, 0),
  };
};
```

#### Step 4: Register Handlers (handlers/index.ts)

```typescript
export { handleSyncStripePayments, handleInspectStripePayments } from './stripe';
```

#### Step 5: Add Routes (index.ts)

```typescript
const routeConfig: RouteConfig = {
  advance: {
    // ... existing handlers
    sync_stripe_payments: handleSyncStripePayments,
  },
  inspect: {
    // ... existing handlers
    stripe_payments: handleInspectStripePayments,
  },
};
```

---

## API Reference

### Advance Request Format

```json
{
  "action": "action_name",
  "field1": "value1",
  "field2": 123
}
```

### Inspect Query Formats

**JSON Format:**
```json
{
  "type": "query_type",
  "params": {
    "id": "123",
    "filter": "active"
  }
}
```

**Path Format:**
```
query_type/param1/value1/param2/value2
```

### Standard Response Format

**Success:**
```json
{
  "action": "action_name",
  "success": true,
  "data": { ... }
}
```

**Error:**
```json
{
  "error": "Error message",
  "code": "ERROR_CODE"
}
```

---

## Best Practices

### 1. Validation

Always validate input at the handler level before calling db functions:

```typescript
// Good
if (!field || typeof field !== 'string') {
  throw new Error('Valid field is required');
}

// Also validate format when needed
if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
  throw new Error('Invalid address format');
}
```

### 2. Idempotency

Use upsert patterns for data sync to handle retries:

```typescript
database.run(
  `INSERT INTO records (external_id, ...) VALUES (?, ...)
   ON CONFLICT(external_id) DO UPDATE SET ...`,
  [externalId, ...]
);
```

### 3. Rate Limiting

Enforce limits on batch operations:

```typescript
const MAX_RECORDS_PER_SYNC = 500;

if (records.length > MAX_RECORDS_PER_SYNC) {
  throw new Error(`Maximum ${MAX_RECORDS_PER_SYNC} records per sync`);
}
```

### 4. Data Sanitization

Remove sensitive fields from responses:

```typescript
function sanitizeEntity(entity: Entity): Partial<Entity> {
  return {
    id: entity.id,
    public_field: entity.public_field,
    // Omit: secret_field, internal_hash, etc.
  };
}
```

### 5. Input Hash for Verification

When storing computed results, include a hash of inputs:

```typescript
const inputHash = createHash('sha256')
  .update(JSON.stringify(inputData))
  .digest('hex');

saveComputation(result, inputHash);
```

### 6. Cursor-Based Pagination

Support incremental sync with cursors:

```typescript
// Store cursor after successful sync
updateSyncCursor(entityId, sourceType, newCursor);

// Retrieve cursor for next sync
const cursor = getSyncCursor(entityId, sourceType);
```

---

## Conclusion

This framework provides a robust foundation for building Cartesi rollup applications that need to:

1. **Ingest data** from external sources (Plaid, Stripe, any API)
2. **Store data** deterministically in SQLite
3. **Compute derived values** from stored data
4. **Verify data authenticity** via proofs
5. **Query data** through inspect requests

The modular architecture makes it straightforward to add new data sources by following the established patterns for schema, CRUD operations, handlers, and routing.
