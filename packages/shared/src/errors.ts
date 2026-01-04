export class ValidationError extends Error {
  constructor(
    public field: string,
    public reason: string,
    public fix?: string
  ) {
    super(`Validation failed: ${field} - ${reason}`);
    this.name = 'ValidationError';
  }
}

export class DockerBuildError extends Error {
  constructor(
    public service: string,
    public dockerfile: string,
    public line: number,
    public fix: string
  ) {
    super(`Docker build failed for ${service} at line ${line} in ${dockerfile}`);
    this.name = 'DockerBuildError';
  }
}

export class DatabaseError extends Error {
  constructor(
    public operation: string,
    public table?: string,
    public originalError?: Error
  ) {
    super(`Database error during ${operation}${table ? ` on table ${table}` : ''}`);
    this.name = 'DatabaseError';
    if (originalError) {
      this.stack = originalError.stack;
    }
  }
}

export class ServiceUnavailableError extends Error {
  constructor(
    public service: string,
    public endpoint: string
  ) {
    super(`Service ${service} is unavailable at ${endpoint}`);
    this.name = 'ServiceUnavailableError';
  }
}

export function isRetryableError(error: Error): boolean {
  if (error instanceof ServiceUnavailableError) return true;
  if (error instanceof DatabaseError) return true;
  if (error.message.includes('ECONNREFUSED')) return true;
  if (error.message.includes('ETIMEDOUT')) return true;
  return false;
}

export function getErrorFix(error: Error): string | null {
  if (error instanceof ValidationError && error.fix) {
    return error.fix;
  }
  if (error instanceof DockerBuildError) {
    return error.fix;
  }
  return null;
}

