import { Module } from '@nestjs/common';
import { APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { ThrottlerModule } from '@nestjs/throttler';
import { Interceptor } from './interceptor';
import { RateLimitGuard } from './rate.limit';

@Module({
  imports: [
    ThrottlerModule.forRoot({
      throttlers: [
        {
          ttl: 60,
          limit: 10,
        },
      ],
    }),
  ],
  providers: [
    {
      provide: APP_GUARD,
      useClass: RateLimitGuard, // custom guard with logging
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: Interceptor,
    },
  ],
  exports: [],
})
export class SecurityModule {}