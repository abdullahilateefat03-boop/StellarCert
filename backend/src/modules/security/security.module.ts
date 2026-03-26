import { Module } from '@nestjs/common';
import { ThrottlerModule } from '@nestjs/throttler';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { RateLimitGuard } from './rate-limit.guard';
import { SecurityHeadersInterceptor } from './security-headers.interceptor';
import { RequestValidationPipe } from './request-validation.pipe';
import { CommonModule } from '../../common/common.module';

@Module({
  imports: [
    ThrottlerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        throttlers: [
          {
            ttl: config.get('THROTTLE_TTL', 60) * 1000, // in ms
            limit: config.get('THROTTLE_LIMIT', 10),
          },
        ],
      }),
    }),
    CommonModule,
  ],
  providers: [
    RateLimitGuard,
    SecurityHeadersInterceptor,
    RequestValidationPipe,
  ],
  exports: [RateLimitGuard, SecurityHeadersInterceptor, RequestValidationPipe],
})
export class SecurityModule {}
