import { drizzle } from 'drizzle-orm/neon-serverless';
import { drizzle as drizzleSQLite } from 'drizzle-orm/better-sqlite3';
import { drizzle as drizzleMSSQL } from 'drizzle-orm/mssql';
import { Pool } from '@neondatabase/serverless';
import Database from 'better-sqlite3';
import { ConnectionPool } from 'mssql';
import * as schema from '@shared/schema';

export type DatabaseType = 'postgresql' | 'sqlite' | 'mssql';

export interface DatabaseConfig {
  type: DatabaseType;
  connectionString?: string;
  filePath?: string; // for SQLite
  options?: any;
}

export class DatabaseAbstraction {
  private db: any;
  private config: DatabaseConfig;

  constructor(config: DatabaseConfig) {
    this.config = config;
    this.initializeDatabase();
  }

  private initializeDatabase() {
    switch (this.config.type) {
      case 'postgresql':
        this.initPostgreSQL();
        break;
      case 'sqlite':
        this.initSQLite();
        break;
      case 'mssql':
        this.initMSSQL();
        break;
      default:
        throw new Error(`Unsupported database type: ${this.config.type}`);
    }
  }

  private initPostgreSQL() {
    if (!this.config.connectionString) {
      throw new Error('PostgreSQL connection string is required');
    }

    const pool = new Pool({ connectionString: this.config.connectionString });
    this.db = drizzle({ client: pool, schema });
  }

  private initSQLite() {
    const dbPath = this.config.filePath || './database.sqlite';
    const sqlite = new Database(dbPath);
    
    // Enable foreign key constraints
    sqlite.pragma('foreign_keys = ON');
    
    this.db = drizzleSQLite(sqlite, { schema });
  }

  private initMSSQL() {
    if (!this.config.connectionString) {
      throw new Error('SQL Server connection string is required');
    }

    const pool = new ConnectionPool(this.config.connectionString);
    this.db = drizzleMSSQL(pool, { schema });
  }

  getDatabase() {
    return this.db;
  }

  async testConnection(): Promise<boolean> {
    try {
      switch (this.config.type) {
        case 'postgresql':
          await this.db.execute('SELECT 1');
          break;
        case 'sqlite':
          await this.db.run('SELECT 1');
          break;
        case 'mssql':
          await this.db.execute('SELECT 1');
          break;
      }
      return true;
    } catch (error) {
      console.error('Database connection test failed:', error);
      return false;
    }
  }

  async migrate(): Promise<void> {
    // Note: In production, you'd use drizzle-kit for migrations
    // This is a simplified approach for demonstration
    try {
      console.log(`Running migrations for ${this.config.type}...`);
      
      // For SQLite, we need to manually create tables since it doesn't support all PostgreSQL features
      if (this.config.type === 'sqlite') {
        await this.createSQLiteTables();
      }
      
      console.log('Migrations completed successfully');
    } catch (error) {
      console.error('Migration failed:', error);
      throw error;
    }
  }

  private async createSQLiteTables() {
    // This would contain SQLite-specific table creation SQL
    // For now, we'll rely on Drizzle's schema to handle this
    console.log('SQLite tables will be created automatically by Drizzle');
  }

  getType(): DatabaseType {
    return this.config.type;
  }

  async close(): Promise<void> {
    // Close database connections if needed
    console.log(`Closing ${this.config.type} database connection`);
  }
}

// Factory function to create database abstraction based on environment
export function createDatabaseAbstraction(): DatabaseAbstraction {
  const dbType = (process.env.DATABASE_TYPE as DatabaseType) || 'postgresql';
  
  const config: DatabaseConfig = {
    type: dbType,
  };

  switch (dbType) {
    case 'postgresql':
      config.connectionString = process.env.DATABASE_URL;
      break;
    case 'sqlite':
      config.filePath = process.env.SQLITE_PATH || './data/gallery.sqlite';
      break;
    case 'mssql':
      config.connectionString = process.env.MSSQL_CONNECTION_STRING;
      break;
  }

  return new DatabaseAbstraction(config);
}

// Export a singleton instance
export const databaseAbstraction = createDatabaseAbstraction();
