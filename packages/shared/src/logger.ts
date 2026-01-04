import winston from 'winston';
import { getConfig } from './config.js';

const config = getConfig();

// Ensure logs directory exists
import { mkdirSync } from 'fs';
import { dirname } from 'path';
try {
  mkdirSync(dirname(config.logging.file), { recursive: true });
  mkdirSync(dirname(config.logging.errorFile), { recursive: true });
} catch (err) {
  // Directory might already exist
}

export const logger = winston.createLogger({
  level: config.logging.level,
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.splat(),
    winston.format.json()
  ),
  defaultMeta: { service: 'ctf-platform' },
  transports: [
    new winston.transports.File({ 
      filename: config.logging.errorFile, 
      level: 'error',
      maxsize: 5242880, // 5MB
      maxFiles: 5,
    }),
    new winston.transports.File({ 
      filename: config.logging.file,
      maxsize: 5242880, // 5MB
      maxFiles: 5,
    }),
  ],
});

// Add console transport in development
if (config.nodeEnv !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.printf(({ timestamp, level, message, service, ...meta }) => {
        const metaStr = Object.keys(meta).length ? JSON.stringify(meta, null, 2) : '';
        return `${timestamp} [${service || 'ctf-platform'}] ${level}: ${message} ${metaStr}`;
      })
    )
  }));
}

export default logger;

