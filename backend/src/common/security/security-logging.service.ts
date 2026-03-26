import { Injectable } from '@nestjs/common';
import { Request } from 'express';
import { LoggingService } from '../logging/logging.service';
import { MetricsService } from '../monitoring/metrics.service';

export enum SecurityEventType {
  RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
  BRUTE_FORCE_DETECTED = 'BRUTE_FORCE_DETECTED',
  INVALID_CSRF_TOKEN = 'INVALID_CSRF_TOKEN',
  SUSPICIOUS_PAYLOAD = 'SUSPICIOUS_PAYLOAD',
  SECURITY_HEADER_MISSING = 'SECURITY_HEADER_MISSING',
  UNAUTHORIZED_ACCESS = 'UNAUTHORIZED_ACCESS',
  SQL_INJECTION_ATTEMPT = 'SQL_INJECTION_ATTEMPT',
  XSS_ATTEMPT = 'XSS_ATTEMPT',
  REQUEST_SIZE_EXCEEDED = 'REQUEST_SIZE_EXCEEDED',
  INVALID_REQUEST = 'INVALID_REQUEST',
}

export interface SecurityEvent {
  type: SecurityEventType;
  timestamp: number;
  identifier: string;
  ip: string;
  userAgent?: string;
  path: string;
  method: string;
  details?: Record<string, any>;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

/**
 * Service for logging security events and blocked requests
 * Provides centralized security monitoring and auditing
 */
@Injectable()
export class SecurityLoggingService {
  private readonly securityEventBuffer: SecurityEvent[] = [];
  private readonly maxBufferSize: number = 1000;

  constructor(
    private readonly loggingService: LoggingService,
    private readonly metricsService: MetricsService,
  ) {
    // Flush security events periodically (every 5 minutes)
    setInterval(() => this.flushSecurityEvents(), 5 * 60 * 1000);
  }

  /**
   * Log a security event
   */
  logSecurityEvent(
    type: SecurityEventType,
    request: Request,
    severity: 'low' | 'medium' | 'high' | 'critical' = 'medium',
    details?: Record<string, any>,
  ): void {
    const event: SecurityEvent = {
      type,
      timestamp: Date.now(),
      identifier: this.extractIdentifier(request),
      ip: this.getClientIp(request),
      userAgent: request.get('user-agent'),
      path: request.path,
      method: request.method,
      details,
      severity,
    };

    this.securityEventBuffer.push(event);
    this.metricsService.incrementCounter(`security_event_${type}`);
    this.metricsService.incrementCounter(`security_severity_${severity}`);

    // Log immediately for critical events
    if (severity === 'high') {
      this.loggingService.warn({
        message: `SECURITY EVENT: ${type}`,
        event,
      });
    } else {
      this.loggingService.info({
        message: `Security: ${type}`,
        event,
      });
    }

    // Flush if buffer is getting too large
    if (this.securityEventBuffer.length >= this.maxBufferSize) {
      this.flushSecurityEvents();
    }
  }

  /**
   * Log rate limit exceeded
   */
  logRateLimitExceeded(request: Request, details: Record<string, any>): void {
    this.logSecurityEvent(
      SecurityEventType.RATE_LIMIT_EXCEEDED,
      request,
      'medium',
      {
        ...details,
        timestamp: new Date().toISOString(),
      },
    );
  }

  /**
   * Log brute force detection
   */
  logBruteForceDetected(request: Request, details: Record<string, any>): void {
    this.logSecurityEvent(
      SecurityEventType.BRUTE_FORCE_DETECTED,
      request,
      'high',
      {
        ...details,
        timestamp: new Date().toISOString(),
      },
    );
  }

  /**
   * Log suspicious payload detection
   */
  logSuspiciousPayload(
    request: Request,
    reason: string,
    details?: Record<string, any>,
  ): void {
    this.logSecurityEvent(
      SecurityEventType.SUSPICIOUS_PAYLOAD,
      request,
      'medium',
      {
        reason,
        ...details,
        timestamp: new Date().toISOString(),
      },
    );
  }

  /**
   * Log unauthorized access attempts
   */
  logUnauthorizedAccess(request: Request, reason: string): void {
    this.logSecurityEvent(
      SecurityEventType.UNAUTHORIZED_ACCESS,
      request,
      'high',
      {
        reason,
        timestamp: new Date().toISOString(),
      },
    );
  }

  /**
   * Log request size exceeded
   */
  logRequestSizeExceeded(request: Request, size: number, limit: number): void {
    this.logSecurityEvent(
      SecurityEventType.REQUEST_SIZE_EXCEEDED,
      request,
      'medium',
      {
        actualSize: size,
        limit,
        exceedByBytes: size - limit,
        timestamp: new Date().toISOString(),
      },
    );
  }

  /**
   * Log potential SQL injection attempt
   */
  logSQLInjectionAttempt(request: Request, suspiciousData: any): void {
    this.logSecurityEvent(
      SecurityEventType.SQL_INJECTION_ATTEMPT,
      request,
      'critical',
      {
        suspiciousData: JSON.stringify(suspiciousData).substring(0, 500),
        timestamp: new Date().toISOString(),
      },
    );
  }

  /**
   * Log potential XSS attempt
   */
  logXSSAttempt(request: Request, suspiciousData: string): void {
    this.logSecurityEvent(SecurityEventType.XSS_ATTEMPT, request, 'high', {
      suspiciousData: suspiciousData.substring(0, 500),
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Get security events for analysis (for admin dashboard)
   */
  getRecentSecurityEvents(limit: number = 100): SecurityEvent[] {
    return this.securityEventBuffer.slice(-limit);
  }

  /**
   * Get security event statistics
   */
  getSecurityStats(): {
    totalEvents: number;
    eventsByType: Record<string, number>;
    eventsBySeverity: Record<string, number>;
  } {
    const eventsByType: Record<string, number> = {};
    const eventsBySeverity: Record<string, number> = {};

    for (const event of this.securityEventBuffer) {
      eventsByType[event.type] = (eventsByType[event.type] || 0) + 1;
      eventsBySeverity[event.severity] =
        (eventsBySeverity[event.severity] || 0) + 1;
    }

    return {
      totalEvents: this.securityEventBuffer.length,
      eventsByType,
      eventsBySeverity,
    };
  }

  /**
   * Flush security events (typically to persistent storage)
   * Override this method to send to external service (e.g., logging platform)
   */
  private flushSecurityEvents(): void {
    if (this.securityEventBuffer.length === 0) {
      return;
    }

    const eventCount = this.securityEventBuffer.length;
    this.loggingService.info(
      `Flushing ${eventCount} security events to persistent storage`,
    );

    // Here you could send to external logging service like:
    // - Sentry
    // - Datadog
    // - CloudWatch
    // - ELK Stack
    // - Splunk
    // etc.

    // For now, we keep them in buffer for in-memory access
    // In production, implement proper persistence
  }

  /**
   * Extract identifier from request (user ID, API key, IP, etc.)
   */
  private extractIdentifier(request: Request): string {
    const user = (request as any).user;
    if (user?.id) return user.id;

    const apiKey = request.get('x-api-key');
    if (apiKey) {
      return `api-key:${apiKey.substring(0, 8)}...`;
    }

    return this.getClientIp(request);
  }

  /**
   * Get client IP address from request
   */
  private getClientIp(request: Request): string {
    const forwarded = request.get('x-forwarded-for');
    if (forwarded) {
      return forwarded.split(',')[0].trim();
    }

    return (
      (request as any).connection?.remoteAddress ||
      (request as any).socket?.remoteAddress ||
      'unknown'
    );
  }
}
