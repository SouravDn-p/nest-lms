import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { ApiResponse } from '../types/global';

@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(GlobalExceptionFilter.name);

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();
    const path = request.url;
    const timestamp = new Date().toISOString();

    let status = HttpStatus.INTERNAL_SERVER_ERROR;
    let message = 'Internal server error';
    let error = 'InternalServerError';

    if (exception instanceof HttpException) {
      status = exception.getStatus();
      const exceptionResponse = exception.getResponse();

      if (typeof exceptionResponse === 'string') {
        message = exceptionResponse;
      } else if (typeof exceptionResponse === 'object' && exceptionResponse !== null) {
        const responseObj = exceptionResponse as Record<string, unknown>;
        const raw = responseObj.message;
        if (Array.isArray(raw)) {
          message = raw.join(', ');
        } else if (typeof raw === 'string') {
          message = raw;
        }
      }
      error = exception.constructor.name;
    } else {
      this.logger.error(
        `Unhandled exception: ${String(exception)}`,
        exception instanceof Error ? exception.stack : undefined,
      );
    }

    const errorResponse: ApiResponse<null> = {
      success: false,
      message,
      data: null,
      meta: { statusCode: status, path, timestamp, error },
    };

    response.status(status).json(errorResponse);
  }
}