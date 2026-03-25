import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { GlobalExceptionFilter } from './common/exceptions/global-exception.filter';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { SentryService } from './common/monitoring/sentry.service';
import { LoggingService } from './common/logging/logging.service';
import { MonitoringInterceptor } from './common/monitoring/monitoring.interceptor';
import { MetricsService } from './common/monitoring/metrics.service';
import { VersioningType } from '@nestjs/common';
import helmet from 'helmet';
import { ConfigService } from '@nestjs/config';
import * as express from 'express';
import * as xss from 'xss-clean';
import * as hpp from 'hpp';
import { ValidationPipe } from './modules/security/validation.pipe';
import { CorsMiddleware } from './modules/security/cors.middleware';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  const sentryService = app.get(SentryService);
  const loggingService = app.get(LoggingService);
  const metricsService = app.get(MetricsService);
  const configService = app.get(ConfigService);

  // ✅ Security headers (Helmet)
  app.use(
    helmet({
      contentSecurityPolicy: false,
      hsts: {
        maxAge: configService.get('HSTS_MAX_AGE') || 31536000,
        includeSubDomains: true,
        preload: configService.get('NODE_ENV') === 'production',
      },
    }),
  );

  // ✅ Request size limits
  app.use(express.json({ limit: '10kb' }));
  app.use(express.urlencoded({ limit: '10kb', extended: true }));

  // ✅ Input sanitization
  app.use(xss());
  app.use(hpp());

  // ✅ Custom CORS middleware
  app.use(new CorsMiddleware().use);

  // ✅ Global prefix
  app.setGlobalPrefix('api');

  // ✅ Versioning
  app.enableVersioning({
    type: VersioningType.URI,
    defaultVersion: '1',
  });

  // ✅ Validation
  app.useGlobalPipes(new ValidationPipe());

  // ✅ Exception filter
  app.useGlobalFilters(
    new GlobalExceptionFilter(sentryService, loggingService),
  );

  // ✅ Monitoring
  app.useGlobalInterceptors(
    new MonitoringInterceptor(metricsService, sentryService, loggingService),
  );

  // ✅ Swagger
  const config = new DocumentBuilder()
    .setTitle('StellarCert API')
    .setDescription('Certificate Management System API Documentation')
    .setVersion('1.0')
    .addBearerAuth()
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document);

  const port = process.env.PORT ?? 3000;
  await app.listen(port);

  loggingService.log(`🚀 App running on port ${port}`);
  loggingService.log(`🔐 Security fully enabled`);
}

bootstrap();