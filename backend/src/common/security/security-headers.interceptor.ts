import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import type { Response } from 'express';
import { ConfigService } from '@nestjs/config';

/**
 * Interceptor to add security headers to all HTTP responses
 * Implements HSTS, CSP, X-Frame-Options, X-Content-Type-Options, and other security headers
 */
@Injectable()
export class SecurityHeadersInterceptor implements NestInterceptor {
  private readonly environment: string;
  private readonly cspPolicy: string;
  private readonly hstsMaxAge: number;

  constructor(private readonly configService: ConfigService) {
    this.environment = this.configService.get('NODE_ENV') || 'development';
    this.hstsMaxAge = this.configService.get('HSTS_MAX_AGE') || 31536000; // 1 year

    // Build CSP based on environment
    this.cspPolicy = this.buildCSPPolicy();
  }

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const response = context.switchToHttp().getResponse<Response>();

    // HSTS (HTTP Strict-Transport-Security) - Forces HTTPS
    if (this.environment === 'production') {
      response.setHeader(
        'Strict-Transport-Security',
        `max-age=${this.hstsMaxAge}; includeSubDomains; preload`,
      );
    }

    // CSP (Content Security Policy)
    response.setHeader('Content-Security-Policy', this.cspPolicy);

    // Prevent clickjacking
    response.setHeader('X-Frame-Options', 'DENY');

    // Prevent MIME type sniffing
    response.setHeader('X-Content-Type-Options', 'nosniff');

    // Enable XSS protection (legacy, but good for older browsers)
    response.setHeader('X-XSS-Protection', '1; mode=block');

    // Referrer Policy - Control referrer leaking
    response.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

    // Permissions Policy (formerly Feature-Policy)
    response.setHeader(
      'Permissions-Policy',
      [
        'accelerometer=()',
        'ambient-light-sensor=()',
        'autoplay=()',
        'battery=()',
        'camera=()',
        'geolocation=()',
        'gyroscope=()',
        'magnetometer=()',
        'microphone=()',
        'payment=()',
        'usb=()',
      ].join(', '),
    );

    // Prevent DNS prefetching to improve privacy
    response.setHeader('X-DNS-Prefetch-Control', 'off');

    // Remove powered-by header to avoid revealing tech stack
    response.removeHeader('X-Powered-By');

    return next.handle();
  }

  private buildCSPPolicy(): string {
    const allowedOrigins = this.configService.get('ALLOWED_ORIGINS') || '';
    const originList = allowedOrigins
      .split(',')
      .map((o) => o.trim())
      .filter(Boolean)
      .join(' ');

    const policies = [
      "default-src 'self'",
      `script-src 'self' ${originList}`,
      `style-src 'self' 'unsafe-inline' ${originList}`,
      `img-src 'self' data: https:`,
      `font-src 'self' data:`,
      "connect-src 'self' https:",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ];

    // Add report-uri for production - useful for monitoring CSP violations
    if (this.environment === 'production') {
      const cspReportUri = this.configService.get('CSP_REPORT_URI');
      if (cspReportUri) {
        policies.push(`report-uri ${cspReportUri}`);
      }
    }

    return policies.join('; ');
  }
}
