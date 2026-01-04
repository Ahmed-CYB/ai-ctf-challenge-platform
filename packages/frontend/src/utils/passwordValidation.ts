/**
 * Password Validation Utilities
 * Strong password requirements for security
 */

export interface PasswordValidation {
  isValid: boolean;
  errors: string[];
  requirements: {
    minLength: boolean;
    hasUpperCase: boolean;
    hasLowerCase: boolean;
    hasNumber: boolean;
    hasSpecialChar: boolean;
  };
}

/**
 * Validate password strength
 * Requirements:
 * - Minimum 8 characters
 * - At least one uppercase letter
 * - At least one lowercase letter
 * - At least one number
 * - At least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)
 */
export function validatePassword(password: string): PasswordValidation {
  const errors: string[] = [];
  const requirements = {
    minLength: password.length >= 8,
    hasUpperCase: /[A-Z]/.test(password),
    hasLowerCase: /[a-z]/.test(password),
    hasNumber: /[0-9]/.test(password),
    hasSpecialChar: /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password),
  };

  if (!requirements.minLength) {
    errors.push('Password must be at least 8 characters long');
  }
  if (!requirements.hasUpperCase) {
    errors.push('Password must contain at least one uppercase letter');
  }
  if (!requirements.hasLowerCase) {
    errors.push('Password must contain at least one lowercase letter');
  }
  if (!requirements.hasNumber) {
    errors.push('Password must contain at least one number');
  }
  if (!requirements.hasSpecialChar) {
    errors.push('Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)');
  }

  return {
    isValid: errors.length === 0,
    errors,
    requirements,
  };
}

/**
 * Get password strength indicator
 */
export function getPasswordStrength(password: string): 'weak' | 'medium' | 'strong' {
  const validation = validatePassword(password);
  
  if (!validation.isValid) {
    return 'weak';
  }

  // Count how many requirements are met beyond minimum
  const metRequirements = Object.values(validation.requirements).filter(Boolean).length;
  
  if (metRequirements >= 5 && password.length >= 12) {
    return 'strong';
  } else if (metRequirements >= 4) {
    return 'medium';
  }
  
  return 'weak';
}

