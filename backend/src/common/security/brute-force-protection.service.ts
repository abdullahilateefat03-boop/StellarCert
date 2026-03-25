import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { LoggingService } from '../logging/logging.service';
import { MetricsService } from '../monitoring/metrics.service';

export interface BruteForceCheckResult {
  isBlocked: boolean;
  attemptsRemaining: number;
  lockoutExpiresAt: number | null;
  lockoutDurationSeconds: number | null;
}

interface BruteForceRecord {
  attempts: number;
  firstAttemptAt: number;
  lockedUntil: number | null;
}

/**
 * Service for managing brute force attack protection
 * Tracks failed login attempts and temporarily locks accounts
 */
@Injectable()
export class BruteForceProtectionService {
  private readonly maxAttempts: number;
  private readonly windowMs: number;
  private readonly lockoutDurationMs: number;
  private readonly storage = new Map<string, BruteForceRecord>();

  constructor(
    private readonly configService: ConfigService,
    private readonly loggingService: LoggingService,
    private readonly metricsService: MetricsService,
  ) {
    this.maxAttempts =
      this.configService.get('BRUTE_FORCE_MAX_ATTEMPTS') || 5;
    this.windowMs =
      this.configService.get('BRUTE_FORCE_WINDOW_MS') || 15 * 60 * 1000; // 15 minutes
    this.lockoutDurationMs =
      this.configService.get('BRUTE_FORCE_LOCKOUT_MS') ||
      30 * 60 * 1000; // 30 minutes

    // Clean up old records every 5 minutes
    setInterval(() => this.cleanupOldRecords(), 5 * 60 * 1000);
  }

  /**
   * Check if an identifier is currently blocked due to brute force attempts
   */
  check(identifier: string): BruteForceCheckResult {
    const record = this.storage.get(identifier);
    const now = Date.now();

    // No record exists yet
    if (!record) {
      return {
        isBlocked: false,
        attemptsRemaining: this.maxAttempts,
        lockoutExpiresAt: null,
        lockoutDurationSeconds: null,
      };
    }

    // Account is currently locked
    if (record.lockedUntil && record.lockedUntil > now) {
      const remainingMs = record.lockedUntil - now;
      this.metricsService.incrementCounter('brute_force_lockout');
      this.loggingService.warn(`Brute force lockout for identifier: ${identifier}`, {
        lockoutExpiresAt: record.lockedUntil,
        remainingMs,
      });

      return {
        isBlocked: true,
        attemptsRemaining: 0,
        lockoutExpiresAt: record.lockedUntil,
        lockoutDurationSeconds: Math.ceil(remainingMs / 1000),
      };
    }

    // Window has expired, reset the record
    if (now - record.firstAttemptAt > this.windowMs) {
      this.storage.delete(identifier);
      return {
        isBlocked: false,
        attemptsRemaining: this.maxAttempts,
        lockoutExpiresAt: null,
        lockoutDurationSeconds: null,
      };
    }

    // Still within the window
    return {
      isBlocked: false,
      attemptsRemaining: Math.max(0, this.maxAttempts - record.attempts),
      lockoutExpiresAt: null,
      lockoutDurationSeconds: null,
    };
  }

  /**
   * Record a failed attempt for an identifier
   */
  recordFailedAttempt(identifier: string): BruteForceCheckResult {
    const now = Date.now();
    const record = this.storage.get(identifier) || {
      attempts: 0,
      firstAttemptAt: now,
      lockedUntil: null,
    };

    record.attempts++;
    record.firstAttemptAt = record.firstAttemptAt || now;

    this.metricsService.incrementCounter('failed_login_attempt');

    // Lock the account if max attempts exceeded
    if (record.attempts >= this.maxAttempts) {
      record.lockedUntil = now + this.lockoutDurationMs;
      this.metricsService.incrementCounter('brute_force_lockout_triggered');

      this.loggingService.error(
        `Brute force lockout triggered for identifier: ${identifier}`,
        {
          attempts: record.attempts,
          maxAttempts: this.maxAttempts,
          lockoutUntil: record.lockedUntil,
        },
      );
    }

    this.storage.set(identifier, record);

    return {
      isBlocked: record.lockedUntil ? record.lockedUntil > now : false,
      attemptsRemaining: Math.max(0, this.maxAttempts - record.attempts),
      lockoutExpiresAt: record.lockedUntil,
      lockoutDurationSeconds: record.lockedUntil
        ? Math.ceil((record.lockedUntil - now) / 1000)
        : null,
    };
  }

  /**
   * Clear brute force attempts for a successful login
   */
  clearFailedAttempts(identifier: string): void {
    this.storage.delete(identifier);
    this.metricsService.incrementCounter('login_success_after_attempts');
  }

  /**
   * Manually unlock an identifier (for admin operations)
   */
  unlock(identifier: string): void {
    this.storage.delete(identifier);
    this.loggingService.info(`Brute force lock manually cleared for: ${identifier}`);
  }

  /**
   * Get statistics for monitoring
   */
  getStats(): {
    totalTrackedIdentifiers: number;
    lockedIdentifiers: number;
  } {
    const now = Date.now();
    let lockedCount = 0;

    for (const record of this.storage.values()) {
      if (record.lockedUntil && record.lockedUntil > now) {
        lockedCount++;
      }
    }

    return {
      totalTrackedIdentifiers: this.storage.size,
      lockedIdentifiers: lockedCount,
    };
  }

  /**
   * Clean up expired records to prevent memory leaks
   */
  private cleanupOldRecords(): void {
    const now = Date.now();
    let cleanedCount = 0;

    for (const [identifier, record] of this.storage.entries()) {
      // Remove if window has expired and no active lockout
      if (
        now - record.firstAttemptAt > this.windowMs &&
        (!record.lockedUntil || record.lockedUntil < now)
      ) {
        this.storage.delete(identifier);
        cleanedCount++;
      }
    }

    if (cleanedCount > 0) {
      this.loggingService.debug(
        `Cleaned up ${cleanedCount} expired brute force records`,
      );
    }
  }
}
