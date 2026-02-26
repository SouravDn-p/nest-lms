import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy, StrategyOptions } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { UsersService } from '../../users/users.service';
import type { Request } from 'express';
import { JwtConfig } from 'src/config/jwt.config';
import { JwtPayload, JwtUser } from 'src/types/auth.types';

@Injectable()
export class RefreshStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
  constructor(
    private readonly configService: ConfigService,
    private readonly usersService: UsersService,
  ) {
    const jwtConfig = configService.get<JwtConfig>('jwt')!;

    const options: StrategyOptions = {
      jwtFromRequest: ExtractJwt.fromExtractors([
        (request: Request): string | null => {
          const cookies = request.cookies as Record<string, string | undefined>;
          return cookies['refreshToken'] ?? null;
        },
      ]),
      secretOrKey: jwtConfig.refreshSecret,
      passReqToCallback: true,
    };

    super(options);
  }

  async validate(request: Request, payload: JwtPayload): Promise<JwtUser> {
    const cookies = request.cookies as Record<string, string | undefined>;
    const refreshToken = cookies['refreshToken'];

    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token missing');
    }

    const isValid = await this.usersService.validateRefreshToken(
      payload.sub,
      refreshToken,
    );

    if (!isValid) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }

    return {
      userId: payload.sub,
      email: payload.email,
      role: payload.role,
    };
  }
}