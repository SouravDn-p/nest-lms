import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy, StrategyOptions } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import type { Request } from 'express';
import type { JwtConfig } from 'src/config/jwt.config';
import { JwtPayload, JwtUser } from 'src/types/auth.types';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(private readonly configService: ConfigService) {
    const jwtConfig = configService.get<JwtConfig>('jwt')!;

    const options: StrategyOptions = {
      jwtFromRequest: ExtractJwt.fromExtractors([
        (request: Request): string | null => {
          const cookies = request.cookies as Record<string, string | undefined>;
          return cookies['accessToken'] ?? null;
        },
      ]),
      ignoreExpiration: false,
      secretOrKey: jwtConfig.accessSecret,
    };

    super(options);
  }

  validate(payload: JwtPayload): JwtUser {
    return {
      userId: payload.sub,
      email: payload.email,
      role: payload.role,
    };
  }
}