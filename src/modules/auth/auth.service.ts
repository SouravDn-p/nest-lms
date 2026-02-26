import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { UsersService } from '../users/users.service';
import { CreateUserDto } from '../users/dto/create-user.dto';
import { LoginDto } from '../users/dto/login.dto';
import { CreateUserResponse, SafeUser } from '../users/types/user.types';
import { UserRole } from '../users/schemas/user.schema';
import { JwtConfig } from '../../config/jwt.config';
import { JwtPayload, JwtUser } from 'src/common/types/auth.types';

interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

export interface LoginResult extends TokenPair {
  user: SafeUser;
}

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async register(
    createUserDto: CreateUserDto,
    imagePath: string | null,
  ): Promise<CreateUserResponse> {
    return this.usersService.create(createUserDto, imagePath);
  }

  async login(loginDto: LoginDto): Promise<LoginResult> {
    const user = await this.usersService.findByEmail(loginDto.email);

    if (!user) throw new UnauthorizedException('Invalid credentials');

    const passwordMatch = await bcrypt.compare(
      loginDto.password,
      user.password,
    );
    if (!passwordMatch) throw new UnauthorizedException('Invalid credentials');

    const userId = user.id;
    const tokens = await this.generateTokens(userId, user.email, user.role);

    await this.usersService.updateRefreshToken(userId, tokens.refreshToken);

    return {
      ...tokens,
      user: {
        _id: userId,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role,
        image: user.image,
      },
    };
  }

  async refresh(jwtUser: JwtUser): Promise<TokenPair> {
    const tokens = await this.generateTokens(
      jwtUser.userId,
      jwtUser.email,
      jwtUser.role,
    );
    await this.usersService.updateRefreshToken(
      jwtUser.userId,
      tokens.refreshToken,
    );
    return tokens;
  }

  async logout(userId: string): Promise<void> {
    await this.usersService.updateRefreshToken(userId, null);
  }

  private async generateTokens(
    userId: string,
    email: string,
    role: UserRole,
  ): Promise<TokenPair> {
    const jwtConfig = this.configService.get<JwtConfig>('jwt')!;
    const payload: JwtPayload = { sub: userId, email, role };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: jwtConfig.accessSecret,
        expiresIn: jwtConfig.accessExpiresIn,
      }),
      this.jwtService.signAsync(payload, {
        secret: jwtConfig.refreshSecret,
        expiresIn: jwtConfig.refreshExpiresIn,
      }),
    ]);

    return { accessToken, refreshToken };
  }
}
