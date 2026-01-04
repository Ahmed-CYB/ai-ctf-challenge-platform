/**
 * Structured Logger
 * 
 * Provides consistent logging across the system
 */

export class Logger {
  constructor() {
    this.logLevel = process.env.LOG_LEVEL || 'info';
  }

  /**
   * Log info message
   */
  info(context, message, ...args) {
    if (this.shouldLog('info')) {
      console.log(`[INFO] [${context}] ${message}`, ...args);
    }
  }

  /**
   * Log success message
   */
  success(context, message, ...args) {
    if (this.shouldLog('info')) {
      console.log(`[SUCCESS] [${context}] ${message}`, ...args);
    }
  }

  /**
   * Log warning message
   */
  warn(context, message, ...args) {
    if (this.shouldLog('warn')) {
      console.warn(`[WARN] [${context}] ${message}`, ...args);
    }
  }

  /**
   * Log error message
   */
  error(context, message, stack = null, ...args) {
    if (this.shouldLog('error')) {
      console.error(`[ERROR] [${context}] ${message}`, ...args);
      if (stack && this.logLevel === 'debug') {
        console.error(stack);
      }
    }
  }

  /**
   * Log debug message
   */
  debug(context, message, ...args) {
    if (this.shouldLog('debug')) {
      console.debug(`[DEBUG] [${context}] ${message}`, ...args);
    }
  }

  /**
   * Check if should log at this level
   */
  shouldLog(level) {
    const levels = { debug: 0, info: 1, warn: 2, error: 3 };
    return levels[level] >= levels[this.logLevel];
  }
}


