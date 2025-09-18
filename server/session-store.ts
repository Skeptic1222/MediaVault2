import session from 'express-session';
import ConnectPgSimple from 'connect-pg-simple';
import MemoryStore from 'memorystore';
import { getDatabaseType, rawQuery } from './db-unified';

// Create appropriate session store based on database type
export function createSessionStore(): session.Store {
  const dbType = getDatabaseType();
  
  if (dbType === 'sqlserver') {
    // Use memory store with SQL Server persistence
    const SqlServerStore = MemoryStore(session);
    
    class SqlServerSessionStore extends SqlServerStore {
      constructor() {
        super({
          checkPeriod: 86400000, // Check expired sessions every 24 hours
          ttl: 86400000, // Session TTL: 24 hours
          dispose: async (key: string, value: any) => {
            // Clean up expired sessions from SQL Server
            try {
              await rawQuery('DELETE FROM sessions WHERE sid = @p1', [key]);
            } catch (error) {
              console.error('Error cleaning up expired session:', error);
            }
          }
        });
      }

      async get(sid: string, callback: (err?: any, session?: any) => void) {
        try {
          const result = await rawQuery('SELECT sess, expire FROM sessions WHERE sid = @p1', [sid]);
          
          if (result.recordset && result.recordset.length > 0) {
            const { sess, expire } = result.recordset[0];
            
            // Check if session is expired
            if (new Date() > new Date(expire)) {
              await this.destroy(sid, callback);
              return;
            }
            
            callback(null, JSON.parse(sess));
          } else {
            callback(null, null);
          }
        } catch (error) {
          callback(error);
        }
      }

      async set(sid: string, session: any, callback?: (err?: any) => void) {
        try {
          const sess = JSON.stringify(session);
          const expire = new Date(Date.now() + 86400000); // 24 hours from now
          
          await rawQuery(`
            IF EXISTS (SELECT 1 FROM sessions WHERE sid = @p1)
              UPDATE sessions SET sess = @p2, expire = @p3 WHERE sid = @p1
            ELSE
              INSERT INTO sessions (sid, sess, expire) VALUES (@p1, @p2, @p3)
          `, [sid, sess, expire]);
          
          if (callback) callback(null);
        } catch (error) {
          if (callback) callback(error);
        }
      }

      async destroy(sid: string, callback?: (err?: any) => void) {
        try {
          await rawQuery('DELETE FROM sessions WHERE sid = @p1', [sid]);
          if (callback) callback(null);
        } catch (error) {
          if (callback) callback(error);
        }
      }

      async all(callback: (err?: any, obj?: any) => void) {
        try {
          const result = await rawQuery('SELECT sid, sess FROM sessions WHERE expire > GETDATE()');
          const sessions: any = {};
          
          if (result.recordset) {
            result.recordset.forEach((row: any) => {
              sessions[row.sid] = JSON.parse(row.sess);
            });
          }
          
          callback(null, sessions);
        } catch (error) {
          callback(error);
        }
      }

      async clear(callback?: (err?: any) => void) {
        try {
          await rawQuery('DELETE FROM sessions');
          if (callback) callback(null);
        } catch (error) {
          if (callback) callback(error);
        }
      }

      async length(callback: (err?: any, length?: number) => void) {
        try {
          const result = await rawQuery('SELECT COUNT(*) as count FROM sessions WHERE expire > GETDATE()');
          const count = result.recordset?.[0]?.count || 0;
          callback(null, count);
        } catch (error) {
          callback(error);
        }
      }

      async touch(sid: string, session: any, callback?: (err?: any) => void) {
        try {
          const expire = new Date(Date.now() + 86400000); // 24 hours from now
          await rawQuery('UPDATE sessions SET expire = @p1 WHERE sid = @p2', [expire, sid]);
          if (callback) callback(null);
        } catch (error) {
          if (callback) callback(error);
        }
      }
    }

    return new SqlServerSessionStore();
    
  } else {
    // Use PostgreSQL store for Replit development
    const PgSession = ConnectPgSimple(session);
    
    return new PgSession({
      conString: process.env.DATABASE_URL,
      tableName: 'sessions',
      createTableIfMissing: true,
    });
  }
}

// Export session configuration
export function getSessionConfig(): session.SessionOptions {
  return {
    store: createSessionStore(),
    secret: process.env.SESSION_SECRET || 'your-secret-key-change-in-production',
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
      secure: process.env.NODE_ENV === 'production' && process.env.HTTPS === 'true',
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
      sameSite: 'strict'
    },
    name: 'securegallery.sid'
  };
}