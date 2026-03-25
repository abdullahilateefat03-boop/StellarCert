import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { CorsOptions } from 'cors';
import { LoggingService } from '../logging/logging.service';

/**
 * Service for comprehensive CORS configuration management
 * Provides environment-based CORS settings with security controls
 */
@Injectable()
export class CorsConfigService {
  private readonly environment: string;
  private readonly allowedOrigins: string[];
  private readonly allowedMethods: string[];
  private readonly allowedHeaders: string[];
  private readonly exposedHeaders: string[];
  private readonly credentials: boolean;
  private readonly maxAge: number;

  constructor(
    private readonly configService: ConfigService,
    private readonly loggingService: LoggingService,
  ) {
    this.environment = this.configService.get('NODE_ENV') || 'development';
    this.allowedOrigins = this.parseOrigins();
    this.allowedMethods = this.getAllowedMethods();
    this.allowedHeaders = this.getAllowedHeaders();
    this.exposedHeaders = this.getExposedHeaders();
    this.credentials = this.configService.get('CORS_CREDENTIALS') !== 'false';
    this.maxAge = this.configService.get('CORS_MAX_AGE') || 86400; // 24 hours

    this.logConfiguration();
  }

  /**
   * Get CORS options for Express/NestJS
   */
  getCorsOptions(): CorsOptions {
    return {
      origin: (origin, callback) => this.validateOrigin(origin, callback),
      methods: this.allowedMethods,
      allowedHeaders: this.allowedHeaders,
      exposedHeaders: this.exposedHeaders,
      credentials: this.credentials,
      maxAge: this.maxAge,
      preflightContinue: false,
    };
  }

  /**
   * Parse allowed origins from environment config
   */
  private parseOrigins(): string[] {
    const originsEnv = this.configService.get('ALLOWED_ORIGINS') || '';
    const defaultOrigins = this.getDefaultOrigins();

    if (this.environment === 'development') {
      return [
        ...defaultOrigins,
        'http://localhost:3000',
        'http://localhost:3001',
        'http://localhost:5173', // Vite default
        'http://127.0.0.1:5173',
      ];
    }

    const customOrigins = originsEnv
      .split(',')
      .map((o) => o.trim())
      .filter(Boolean);

    return customOrigins.length > 0 ? customOrigins : defaultOrigins;
  }

  /**
   * Get default allowed origins
   */
  private getDefaultOrigins(): string[] {
    switch (this.environment) {
      case 'production':
        return [
          'https://app.example.com', // Change to your production domain
          'https://www.example.com',
        ];
      case 'staging':
        return ['https://staging.example.com'];
      default:
        return ['http://localhost:3000'];
    }
  }

  /**
   * Get allowed HTTP methods
   */
  private getAllowedMethods(): string[] {
    return ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE', 'OPTIONS'];
  }

  /**
   * Get allowed request headers
   */
  private getAllowedHeaders(): string[] {
    return [
      'Origin',
      'X-Requested-With',
      'Content-Type',
      'Accept',
      'Accept-Language',
      'Authorization',
      'X-API-Key',
      'X-CSRF-Token',
      'X-Client-ID',
      'X-Request-ID',
    ];
  }

  /**
   * Get headers exposed to the client
   */
  private getExposedHeaders(): string[] {
    return [
      'X-RateLimit-Limit',
      'X-RateLimit-Remaining',
      'X-RateLimit-Reset',
      'Retry-After',
      'X-Request-ID',
      'X-Total-Count',
      'X-Page-Number',
      'X-Page-Size',
    ];
  }

  /**
   * Validate origin against allowed list
   */
  private validateOrigin(
    origin: string | undefined,
    callback: (err: Error | null, allow?: boolean) => void,
  ): void {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) {
      callback(null, true);
      return;
    }

    // Check if origin is in the allowed list
    const isAllowed = this.allowedOrigins.some((allowed) => {
      // Exact match
      if (allowed === origin) {
        return true;
      }

      // Wildcard support for subdomains (e.g., *.example.com)
      if (allowed.startsWith('*.')) {
        const domain = allowed.substring(2);
        return origin.endsWith(domain);
      }

      return false;
    });

    if (isAllowed) {
      callback(null, true);
    } else {
      this.loggingService.warn(`CORS request from disallowed origin: ${origin}`);
      callback(new Error('CORS policy: Origin not allowed'), false);
    }
  }

  /**
   * Add a dynamic origin (e.g., for user-configured webhooks)
   */
  addDynamicOrigin(origin: string): void {
    if (!this.allowedOrigins.includes(origin)) {
      this.allowedOrigins.push(origin);
      this.loggingService.info(`Added dynamic CORS origin: ${origin}`);
    }
  }

  /**
   * Remove a dynamic origin
   */
  removeDynamicOrigin(origin: string): void {
    const index = this.allowedOrigins.indexOf(origin);
    if (index > -1) {
      this.allowedOrigins.splice(index, 1);
      this.loggingService.info(`Removed CORS origin: ${origin}`);
    }
  }

  /**
   * Get list of allowed origins
   */
  getAllowedOrigins(): string[] {
    return [...this.allowedOrigins];
  }

  /**
   * Log CORS configuration for debugging
   */
  private logConfiguration(): void {
    this.loggingService.debug('CORS Configuration', {
      environment: this.environment,
      allowedOrigins: this.allowedOrigins,
      allowedMethods: this.allowedMethods,
      allowedHeaders: this.allowedHeaders,
      exposedHeaders: this.exposedHeaders,
      credentials: this.credentials,
      maxAge: this.maxAge,
    });
  }
}
