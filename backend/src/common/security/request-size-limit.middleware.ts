import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { ConfigService } from '@nestjs/config';
import { SecurityLoggingService } from './security-logging.service';

/**
 * Middleware for enforcing request size limits
 * Prevents denial-of-service attacks through massive payloads
 */
@Injectable()
export class RequestSizeLimitMiddleware implements NestMiddleware {
  private readonly maxJsonSize: string;
  private readonly maxUrlEncodedSize: string;

  constructor(
    private readonly configService: ConfigService,
    private readonly securityLoggingService: SecurityLoggingService,
  ) {
    this.maxJsonSize = this.configService.get('MAX_JSON_SIZE') || '100kb';
    this.maxUrlEncodedSize =
      this.configService.get('MAX_URL_ENCODED_SIZE') || '100kb';
  }

  use(req: Request, res: Response, next: NextFunction): void {
    const contentLength = parseInt(req.get('content-length') || '0', 10);

    // Parse size limit in bytes
    const maxSize = this.parseSize(this.maxJsonSize);

    if (contentLength > maxSize) {
      this.securityLoggingService.logRequestSizeExceeded(
        req,
        contentLength,
        maxSize,
      );

      res.status(413).json({
        statusCode: 413,
        message: `Payload too large. Maximum size: ${this.maxJsonSize}`,
        error: 'Payload Too Large',
      });
      return;
    }

    next();
  }

  /**
   * Parse size string (e.g., "100kb") to bytes
   */
  private parseSize(size: string): number {
    const units: Record<string, number> = {
      b: 1,
      kb: 1024,
      mb: 1024 * 1024,
      gb: 1024 * 1024 * 1024,
    };

    const match = size.toLowerCase().match(/^(\d+)([a-z]+)$/);
    if (!match) {
      return parseInt(size, 10);
    }

    const [, value, unit] = match;
    return parseInt(value, 10) * (units[unit] || 1);
  }
}
