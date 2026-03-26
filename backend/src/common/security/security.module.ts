import { Module, MiddlewareConsumer, NestModule } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { SecurityHeadersInterceptor } from './security-headers.interceptor';
import { BruteForceProtectionService } from './brute-force-protection.service';
import { SanitizationService, SanitizationPipe } from './sanitization.service';
import { SecurityLoggingService } from './security-logging.service';
import { CorsConfigService } from './cors-config.service';
import { RequestSizeLimitMiddleware } from './request-size-limit.middleware';
import { APP_INTERCEPTOR } from '@nestjs/core';

/**
 * SecurityModule provides comprehensive API security features:
 *
 * - Security Headers (HSTS, CSP, X-Frame-Options, etc.)
 * - Rate Limiting (per endpoint/user)
 * - CORS Configuration
 * - Brute Force Protection
 * - Input Sanitization
 * - Request Size Limits
 * - Security Event Logging
 *
 * Export all security services for use in other modules
 */
@Module({
  imports: [ConfigModule],
  providers: [
    // Global security headers interceptor
    {
      provide: APP_INTERCEPTOR,
      useClass: SecurityHeadersInterceptor,
    },
    // Security services
    BruteForceProtectionService,
    SanitizationService,
    SanitizationPipe,
    SecurityLoggingService,
    CorsConfigService,
  ],
  exports: [
    SecurityHeadersInterceptor,
    BruteForceProtectionService,
    SanitizationService,
    SanitizationPipe,
    SecurityLoggingService,
    CorsConfigService,
    RequestSizeLimitMiddleware,
  ],
})
export class SecurityModule implements NestModule {
  constructor(
    private readonly bruteForceService: BruteForceProtectionService,
    private readonly securityLoggingService: SecurityLoggingService,
  ) {}

  /**
   * Configure middleware for request size limiting
   */
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(RequestSizeLimitMiddleware).forRoutes('*');
  }
}
