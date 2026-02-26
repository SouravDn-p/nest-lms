import { registerAs } from '@nestjs/config';

export interface JwtConfig {
  accessSecret: string;
  refreshSecret: string;
  accessExpiresIn: number;
  refreshExpiresIn: number;
}

export default registerAs<JwtConfig>('jwt', (): JwtConfig => ({
  accessSecret: process.env.JWT_ACCESS_SECRET ?? 'fallback-access-secret',
  refreshSecret: process.env.JWT_REFRESH_SECRET ?? 'fallback-refresh-secret',
  accessExpiresIn: Number(process.env.JWT_ACCESS_EXPIRES_IN) || 900,
  refreshExpiresIn: Number(process.env.JWT_REFRESH_EXPIRES_IN) || 604800,
}));