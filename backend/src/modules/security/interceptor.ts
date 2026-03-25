import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor,
} from '@nestjs/common';
import { map } from 'rxjs/operators';

@Injectable()
export class Interceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler) {
    const response = context.switchToHttp().getResponse();

    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('X-Frame-Options', 'DENY');
    response.setHeader('X-XSS-Protection', '1; mode=block');
    response.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline';",
    );

    return next.handle().pipe(map((data) => data));
  }
}