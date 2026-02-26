import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { MulterModule } from '@nestjs/platform-express';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { UsersModule } from '../users/users.module';
import { JwtStrategy } from './strategies/jwt.strategy';
import { RefreshStrategy } from './strategies/refresh.strategy';

@Module({
  imports: [
    UsersModule,
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.register({}), // secrets injected per-call in auth.service.ts
    MulterModule.register({ dest: './uploads/avatars' }),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy, RefreshStrategy],
  exports: [AuthService],
})
export class AuthModule {}