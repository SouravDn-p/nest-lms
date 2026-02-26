import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { Request, Response } from 'express';
import { ApiResponse } from 'src/types/global';

@Injectable()
export class ResponseInterceptor<T> implements NestInterceptor<
  T,
  ApiResponse<T>
> {
  intercept(
    context: ExecutionContext,
    next: CallHandler,
  ): Observable<ApiResponse<T>> {
    return next.handle().pipe(
      map((data: T) => {
        if (this.isApiResponse(data)) {
          return data as ApiResponse<T>;
        }

        const httpContext = context.switchToHttp();
        const response = httpContext.getResponse<Response>();
        const request = httpContext.getRequest<Request>();
        const statusCode: number = response.statusCode;
        const path: string = request.url;
        const timestamp = new Date().toISOString();

        return {
          success: true,
          message: this.getSuccessMessage(statusCode),
          data,
          meta: { statusCode, path, timestamp },
        };
      }),
    );
  }

  private isApiResponse(data: unknown): boolean {
    return (
      data !== null &&
      typeof data === 'object' &&
      'success' in data &&
      'message' in data
    );
  }

  private getSuccessMessage(statusCode: number): string {
    switch (statusCode) {
      case 200:
        return 'Request successful';
      case 201:
         return 'Resource created successfully';
      case 204:
         return 'Request processed successfully';
      default:
          return 'Operation completed successfully';
    }
  }
}