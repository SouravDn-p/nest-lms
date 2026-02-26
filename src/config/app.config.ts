import { registerAs } from '@nestjs/config';

export interface AppConfig {
  port: number;
  env: string;
}

export default registerAs<AppConfig>(
  'app',
  (): AppConfig => ({
    port: Number(process.env.PORT) || 5000,
    env: process.env.NODE_ENV || 'development',
  }),
);
