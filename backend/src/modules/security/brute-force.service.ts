import {
  CanActivate,
  ExecutionContext,
  Injectable,
  ForbiddenException,
} from '@nestjs/common';

const attempts = new Map<string, { count: number; lastAttempt: number }>();

@Injectable()
export class BruteForceGuard implements CanActivate {
  private MAX_ATTEMPTS = 5;
  private BLOCK_TIME = 60 * 1000; // 1 minute

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const ip = request.ip;

    const now = Date.now();
    const record = attempts.get(ip);

    if (!record) {
      attempts.set(ip, { count: 1, lastAttempt: now });
      return true;
    }

    if (now - record.lastAttempt > this.BLOCK_TIME) {
      attempts.set(ip, { count: 1, lastAttempt: now });
      return true;
    }

    record.count++;
    record.lastAttempt = now;

    if (record.count > this.MAX_ATTEMPTS) {
      throw new ForbiddenException('Too many failed attempts. Try later.');
    }

    return true;
  }
}