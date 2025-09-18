import { drizzle } from 'drizzle-orm/node-postgres';
import { drizzle as drizzleMssql } from 'drizzle-orm/mssql';
import pkg from 'pg';
import * as sql from 'mssql';

// Database adapter interface for multi-database support
export interface DatabaseAdapter {
  query(sql: string, params?: any[]): Promise<any>;
  close(): Promise<void>;
}

// PostgreSQL adapter (for Replit development)
export class PostgreSQLAdapter implements DatabaseAdapter {
  private client: pkg.Client;
  private db: any;

  constructor(connectionString: string) {
    this.client = new pkg.Client({ connectionString });
    this.db = drizzle(this.client);
  }

  async connect() {
    await this.client.connect();
  }

  async query(sqlQuery: string, params?: any[]) {
    return await this.client.query(sqlQuery, params);
  }

  async close() {
    await this.client.end();
  }

  getDb() {
    return this.db;
  }
}

// SQL Server adapter (for Windows deployment)
export class SQLServerAdapter implements DatabaseAdapter {
  private pool: sql.ConnectionPool;
  private db: any;

  constructor(config: sql.config) {
    this.pool = new sql.ConnectionPool(config);
    this.db = drizzleMssql(this.pool);
  }

  async connect() {
    await this.pool.connect();
  }

  async query(sqlQuery: string, params?: any[]) {
    const request = this.pool.request();
    
    // Convert PostgreSQL-style parameters ($1, $2) to SQL Server-style (@p1, @p2)
    let convertedQuery = sqlQuery;
    if (params) {
      params.forEach((param, index) => {
        const pgParam = `$${index + 1}`;
        const sqlServerParam = `@p${index + 1}`;
        convertedQuery = convertedQuery.replace(new RegExp(`\\${pgParam}`, 'g'), sqlServerParam);
        request.input(`p${index + 1}`, param);
      });
    }

    // Convert PostgreSQL-specific functions to SQL Server equivalents
    convertedQuery = this.convertPostgreSQLToSQLServer(convertedQuery);
    
    return await request.query(convertedQuery);
  }

  private convertPostgreSQLToSQLServer(query: string): string {
    return query
      // UUID generation
      .replace(/gen_random_uuid\(\)/gi, 'NEWID()')
      // JSONB to JSON (SQL Server 2016+)
      .replace(/::jsonb/gi, '')
      .replace(/jsonb/gi, 'NVARCHAR(MAX)')
      // Boolean handling
      .replace(/::boolean/gi, '')
      // Timestamp functions
      .replace(/NOW\(\)/gi, 'GETDATE()')
      .replace(/CURRENT_TIMESTAMP/gi, 'GETDATE()')
      // Array handling (convert to JSON arrays)
      .replace(/text\[\]/gi, 'NVARCHAR(MAX)')
      // Bytea to VARBINARY
      .replace(/bytea/gi, 'VARBINARY(MAX)')
      // ILIKE to LIKE with UPPER/LOWER
      .replace(/ILIKE/gi, 'LIKE')
      // Limit/Offset to TOP/OFFSET-FETCH
      .replace(/LIMIT\s+(\d+)/gi, (match, limit) => {
        return `TOP ${limit}`;
      });
  }

  async close() {
    await this.pool.close();
  }

  getDb() {
    return this.db;
  }
}

// Database factory
export class DatabaseFactory {
  static createAdapter(type: 'postgresql' | 'sqlserver', config: any): DatabaseAdapter {
    switch (type) {
      case 'postgresql':
        return new PostgreSQLAdapter(config.connectionString);
      case 'sqlserver':
        return new SQLServerAdapter(config);
      default:
        throw new Error(`Unsupported database type: ${type}`);
    }
  }
}

// Database configuration
export function getDatabaseConfig() {
  const dbType = process.env.DB_TYPE as 'postgresql' | 'sqlserver' || 'postgresql';
  
  if (dbType === 'sqlserver') {
    return {
      type: 'sqlserver' as const,
      config: {
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
      }
    };
  } else {
    return {
      type: 'postgresql' as const,
      config: {
        connectionString: process.env.DATABASE_URL || 'postgresql://localhost:5432/securegallery'
      }
    };
  }
}

// Global database connection
let dbAdapter: DatabaseAdapter | null = null;

export async function getDatabase() {
  if (!dbAdapter) {
    const config = getDatabaseConfig();
    dbAdapter = DatabaseFactory.createAdapter(config.type, config.config);
    await (dbAdapter as any).connect();
  }
  return dbAdapter;
}

export async function getDb() {
  const adapter = await getDatabase();
  return (adapter as any).getDb();
}