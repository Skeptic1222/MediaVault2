import { drizzle } from 'drizzle-orm/node-postgres';
import { drizzle as drizzleMssql } from 'drizzle-orm/mssql';
import pkg from 'pg';
import * as sql from 'mssql';
import * as schema from '@shared/schema';

// Unified database connection that supports both PostgreSQL and SQL Server
class UnifiedDatabase {
  private static instance: UnifiedDatabase;
  private client: any;
  private db: any;
  private dbType: 'postgresql' | 'sqlserver';

  private constructor() {
    this.dbType = (process.env.DB_TYPE as 'postgresql' | 'sqlserver') || 'postgresql';
  }

  public static getInstance(): UnifiedDatabase {
    if (!UnifiedDatabase.instance) {
      UnifiedDatabase.instance = new UnifiedDatabase();
    }
    return UnifiedDatabase.instance;
  }

  async connect() {
    if (this.client) {
      return this.db; // Already connected
    }

    if (this.dbType === 'sqlserver') {
      const config: sql.config = {
        server: process.env.DB_SERVER || 'localhost\\SQLEXPRESS',
        database: process.env.DB_NAME || 'SecureGalleryPro',
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        pool: {
          max: 10,
          min: 0,
          idleTimeoutMillis: 30000
        },
        options: {
          encrypt: process.env.DB_ENCRYPT === 'true',
          trustServerCertificate: process.env.DB_TRUST_CERTIFICATE === 'true',
          enableArithAbort: true
        }
      };

      this.client = new sql.ConnectionPool(config);
      await this.client.connect();
      
      // Import SQL Server schema for type safety
      this.db = drizzleMssql(this.client, { schema });
      
    } else {
      // PostgreSQL (default for Replit development)
      const connectionString = process.env.DATABASE_URL;
      if (!connectionString) {
        throw new Error('DATABASE_URL environment variable is required for PostgreSQL');
      }

      this.client = new pkg.Client({ connectionString });
      await this.client.connect();
      this.db = drizzle(this.client, { schema });
    }

    console.log(`Connected to ${this.dbType} database successfully`);
    return this.db;
  }

  async close() {
    if (this.client) {
      if (this.dbType === 'sqlserver') {
        await this.client.close();
      } else {
        await this.client.end();
      }
      this.client = null;
      this.db = null;
    }
  }

  getDb() {
    if (!this.db) {
      throw new Error('Database not connected. Call connect() first.');
    }
    return this.db;
  }

  getDbType() {
    return this.dbType;
  }

  // Helper method for SQL Server-specific operations
  async rawQuery(query: string, params?: any[]) {
    if (this.dbType === 'sqlserver') {
      const request = this.client.request();
      if (params) {
        params.forEach((param, index) => {
          request.input(`p${index + 1}`, param);
        });
        // Convert PostgreSQL parameter style to SQL Server
        query = query.replace(/\$(\d+)/g, '@p$1');
      }
      return await request.query(query);
    } else {
      return await this.client.query(query, params);
    }
  }
}

// Export singleton instance
const dbInstance = UnifiedDatabase.getInstance();

export async function connectDatabase() {
  return await dbInstance.connect();
}

export function getDatabase() {
  return dbInstance.getDb();
}

export function getDatabaseType() {
  return dbInstance.getDbType();
}

export async function closeDatabase() {
  await dbInstance.close();
}

export async function rawQuery(query: string, params?: any[]) {
  return await dbInstance.rawQuery(query, params);
}

// Initialize database connection - this will be called by the application
let db: any = null;

export async function initializeDatabase() {
  if (!db) {
    db = await connectDatabase();
  }
  return db;
}

export { db };