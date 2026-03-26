import { Injectable, ExecutionContext } from '@nestjs/common';
import {
  ThrottlerGuard,
  ThrottlerStorage,
  ThrottlerLimitDetail,
} from '@nestjs/throttler';
import type { ThrottlerModuleOptions } from '@nestjs/throttler';
import { Reflector } from '@nestjs/core';
import { SecurityLoggingService } from '../../common/security/security-logging.service';

@Injectable()
export class RateLimitGuard extends ThrottlerGuard {
  constructor(
    options: ThrottlerModuleOptions,
    storageService: ThrottlerStorage,
    reflector: Reflector,
    private readonly securityLogging: SecurityLoggingService,
  ) {
    super(options, storageService, reflector);
  }

  protected async throwThrottlingException(
    context: ExecutionContext,
    throttlerLimitDetail: ThrottlerLimitDetail,
  ): Promise<void> {
    // Log the rate limit exceeded
    const request = context.switchToHttp().getRequest();
    this.securityLogging.logRateLimitExceeded(request, {
      message: 'Rate limit exceeded',
    });
    return super.throwThrottlingException(context, throttlerLimitDetail);
  }
}
