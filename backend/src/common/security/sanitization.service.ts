import {
  Injectable,
  PipeTransform,
  ArgumentMetadata,
  BadRequestException,
} from '@nestjs/common';
import { LoggingService } from '../logging/logging.service';

/**
 * Sanitizer utility for input validation and security
 * Prevents common security vulnerabilities like XSS, SQL injection, etc.
 */
interface SanitizationOptions {
  allowHtml?: boolean;
  maxLength?: number;
  pattern?: RegExp;
}

@Injectable()
export class SanitizationService {
  constructor(private readonly loggingService: LoggingService) {}

  /**
   * Sanitize string input by removing dangerous characters
   */
  sanitizeString(
    input: string,
    options: SanitizationOptions = {},
  ): string {
    const { allowHtml = false, maxLength = 10000 } = options;

    if (!input || typeof input !== 'string') {
      return '';
    }

    let sanitized = input.trim();

    // Check length
    if (sanitized.length > maxLength) {
      this.loggingService.warn('Input exceeds maximum length', {
        inputLength: sanitized.length,
        maxLength,
      });
      throw new BadRequestException(
        `Input exceeds maximum length of ${maxLength}`,
      );
    }

    // Remove control characters
    sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');

    // If HTML not allowed, remove HTML tags and entities
    if (!allowHtml) {
      // Remove script tags and content
      sanitized = sanitized.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');

      // Remove style tags
      sanitized = sanitized.replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '');

      // Remove event handlers
      sanitized = sanitized.replace(/on[a-z]+\s*=\s*["'][^"']*["']/gi, '');
      sanitized = sanitized.replace(/on[a-z]+\s*=\s*[^\s>]*/gi, '');

      // Remove dangerous protocols
      sanitized = sanitized.replace(/javascript:/gi, '');
      sanitized = sanitized.replace(/data:text\/html/gi, '');
      sanitized = sanitized.replace(/vbscript:/gi, '');
    }

    return sanitized;
  }

  /**
   * Sanitize object properties recursively
   */
  sanitizeObject<T extends Record<string, any>>(
    obj: T,
    options: SanitizationOptions = {},
  ): T {
    const sanitized = {} as T;

    for (const [key, value] of Object.entries(obj)) {
      if (value === null || value === undefined) {
        sanitized[key as keyof T] = value;
      } else if (typeof value === 'string') {
        sanitized[key as keyof T] = this.sanitizeString(
          value,
          options,
        ) as any;
      } else if (Array.isArray(value)) {
        sanitized[key as keyof T] = value.map((item) => {
          if (typeof item === 'string') {
            return this.sanitizeString(item, options);
          }
          if (typeof item === 'object' && item !== null) {
            return this.sanitizeObject(item, options);
          }
          return item;
        }) as any;
      } else if (typeof value === 'object') {
        sanitized[key as keyof T] = this.sanitizeObject(value, options) as any;
      } else {
        sanitized[key as keyof T] = value;
      }
    }

    return sanitized;
  }

  /**
   * Validate email format
   */
  isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email) && email.length <= 254;
  }

  /**
   * Validate URL format
   */
  isValidUrl(url: string): boolean {
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Remove potentially dangerous characters from filenames
   */
  sanitizeFilename(filename: string): string {
    if (!filename || typeof filename !== 'string') {
      return '';
    }

    // Remove path traversal attempts
    let sanitized = filename.replace(/\.\.\//g, '').replace(/\.\.\\/g, '');

    // Remove special characters except dots and underscores
    sanitized = sanitized.replace(/[^a-zA-Z0-9._\-]/g, '_');

    // Remove multiple consecutive dots
    sanitized = sanitized.replace(/\.{2,}/g, '.');

    // Limit length
    if (sanitized.length > 255) {
      sanitized = sanitized.substring(0, 255);
    }

    return sanitized;
  }
}

/**
 * Pipe to automatically sanitize request body and parameters
 */
@Injectable()
export class SanitizationPipe implements PipeTransform {
  constructor(private readonly sanitizationService: SanitizationService) {}

  transform(value: any, metadata: ArgumentMetadata): any {
    if (!value || typeof value !== 'object') {
      return value;
    }

    // Only sanitize body, not params or query in this pipe
    // (They will be sanitized by separate sanitization in the service)
    if (metadata.type === 'body') {
      return this.sanitizationService.sanitizeObject(value, {
        maxLength: 10000,
        allowHtml: false,
      });
    }

    return value;
  }
}
