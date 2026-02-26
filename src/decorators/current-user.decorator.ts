import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { JwtUser } from '../types/auth.types';

export const CurrentUser = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): JwtUser => {
    const request = ctx.switchToHttp().getRequest<{ user: JwtUser }>();
    return request.user;
  },
);