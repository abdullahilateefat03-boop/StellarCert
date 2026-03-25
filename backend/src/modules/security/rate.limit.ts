import {
  ExecutionContext,
  Injectable,
  BadRequestException,
} from '@nestjs/common';
import { ThrottlerGuard, ThrottlerRequest } from '@nestjs/throttler';

@Injectable()
export class RateLimitGuard extends ThrottlerGuard {
  protected async handleRequest(requestProps: ThrottlerRequest): Promise<boolean> {
    try {
      return await super.handleRequest(requestProps);
    } catch (err) {
      const req = requestProps.context.switchToHttp().getRequest();

      console.warn(`🚨 Rate limit exceeded -> IP: ${req.ip}, URL: ${req.url}`);

      throw new BadRequestException('Too many requests. Please try again later.');
    }
  }
}