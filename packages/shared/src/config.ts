import { z } from 'zod';
import path from 'path';

const configSchema = z.object({
  nodeEnv: z.enum(['development', 'production', 'test']).default('development'),
  
  database: z.object({
    url: z.string().url(),
    poolSize: z.number().int().positive().default(10),
    ssl: z.boolean().default(false),
  }),
  
  api: z.object({
    port: z.number().int().positive().default(4002),
    corsOrigin: z.string().url().default('http://localhost:4000'),
    jwtSecret: z.string().min(32).default('your-secret-key-change-this-in-production'),
  }),
  
  frontend: z.object({
    port: z.number().int().positive().default(4000),
    apiBaseUrl: z.string().url().default('http://localhost:4002/api'),
  }),
  
  ctf: z.object({
    port: z.number().int().positive().default(4003),
    dockerSocket: z.string().default('/var/run/docker.sock'),
    clonePath: z.string().default('/tmp/ctf-repo'),
  }),
  
  guacamole: z.object({
    port: z.number().int().positive().default(8081),
    dbPort: z.number().int().positive().default(3307),
    dbPassword: z.string().default('guacamole_password_123'),
  }),
  
  logging: z.object({
    level: z.enum(['error', 'warn', 'info', 'debug']).default('info'),
    file: z.string().default('logs/combined.log'),
    errorFile: z.string().default('logs/error.log'),
  }),
});

export type Config = z.infer<typeof configSchema>;

let config: Config | null = null;

export function getConfig(): Config {
  if (config) return config;
  
  config = configSchema.parse({
    nodeEnv: process.env.NODE_ENV || 'development',
    
    database: {
      url: process.env.DATABASE_URL || 'postgresql://ctf_user:ctf_password_123@localhost:5433/ctf_platform',
      poolSize: parseInt(process.env.DB_POOL_SIZE || '10'),
      ssl: process.env.DB_SSL === 'true',
    },
    
    api: {
      port: parseInt(process.env.BACKEND_PORT || '4002'),
      corsOrigin: process.env.FRONTEND_URL || 'http://localhost:4000',
      jwtSecret: process.env.JWT_SECRET || 'your-secret-key-change-this-in-production',
    },
    
    frontend: {
      port: parseInt(process.env.FRONTEND_PORT || '4000'),
      apiBaseUrl: process.env.VITE_API_BASE_URL || 'http://localhost:4002/api',
    },
    
    ctf: {
      port: parseInt(process.env.CTF_API_PORT || '4003'),
      dockerSocket: process.env.DOCKER_SOCKET || '/var/run/docker.sock',
      clonePath: process.env.CLONE_PATH || path.join(process.cwd(), 'challenges-repo'),
    },
    
    guacamole: {
      port: parseInt(process.env.GUACAMOLE_PORT || '8081'),
      dbPort: parseInt(process.env.GUACAMOLE_DB_PORT || '3307'),
      dbPassword: process.env.GUACAMOLE_DB_PASSWORD || 'guacamole_password_123',
    },
    
    logging: {
      level: (process.env.LOG_LEVEL || 'info') as 'error' | 'warn' | 'info' | 'debug',
      file: process.env.LOG_FILE || 'logs/combined.log',
      errorFile: process.env.LOG_ERROR_FILE || 'logs/error.log',
    },
  });
  
  return config;
}

