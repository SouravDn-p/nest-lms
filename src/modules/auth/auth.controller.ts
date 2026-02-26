import {
  Body,
  Controller,
  Post,
  UseGuards,
  Res,
  HttpCode,
  HttpStatus,
  Get,
  UseInterceptors,
  UploadedFile,
  ParseFilePipe,
  MaxFileSizeValidator,
  FileTypeValidator,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { FileInterceptor } from '@nestjs/platform-express';
import { diskStorage } from 'multer';
import { extname } from 'path';
import type { Response } from 'express';
import { AuthService } from './auth.service';
import { CreateUserDto } from '../users/dto/create-user.dto';
import { LoginDto } from '../users/dto/login.dto';

import { CreateUserResponse, SafeUser } from '../users/types/user.types';
import { ApiResponse } from 'src/types/global';
import type { JwtUser } from 'src/types/auth.types';
import { Public } from 'src/decorators/public.decorator';
import { CurrentUser } from 'src/decorators/current-user.decorator';
import { JwtAuthGuard } from 'src/guards/jwt-auth.guard';

const ACCESS_MAX_AGE  = 15 * 60 * 1000;
const REFRESH_MAX_AGE = 7 * 24 * 60 * 60 * 1000;

function buildCookieOptions(maxAge: number) {
  return {
    httpOnly: true,
    secure: process.env['NODE_ENV'] === 'production',
    sameSite: 'strict' as const,
    maxAge,
  };
}

const imageStorage = diskStorage({
  destination: './uploads/avatars',
  filename: (_req, file, cb) => {
    const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
    cb(null, `avatar-${uniqueSuffix}${extname(file.originalname)}`);
  },
});

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // ─── Register ────────────────────────────────────────────────────────────────
  // POST /auth/register
  // Content-Type: multipart/form-data
  // Fields: firstName, lastName, email, password, role? (optional)
  // File:   image (optional, max 2MB, jpeg/png/webp)
  @Post('register')
  @Public()
  @HttpCode(HttpStatus.CREATED)
  @UseInterceptors(FileInterceptor('image', { storage: imageStorage }))
  async register(
    @Body() createUserDto: CreateUserDto,
    @UploadedFile(
      new ParseFilePipe({
        validators: [
          new MaxFileSizeValidator({ maxSize: 2 * 1024 * 1024 }), // 2 MB
          new FileTypeValidator({ fileType: /^image\/(jpeg|png|webp)$/ }),
        ],
        fileIsRequired: false, // image is optional
      }),
    )
    file: Express.Multer.File | undefined,
  ): Promise<ApiResponse<CreateUserResponse>> {
    const imagePath = file ? `/uploads/avatars/${file.filename}` : null;
    const data = await this.authService.register(createUserDto, imagePath);
    return ApiResponse.success(data);
  }

  // ─── Login ───────────────────────────────────────────────────────────────────
  // POST /auth/login  — JSON body
  @Post('login')
  @Public()
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() loginDto: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ApiResponse<{ user: SafeUser }>> {
    const result = await this.authService.login(loginDto);

    res.cookie('accessToken',  result.accessToken,  buildCookieOptions(ACCESS_MAX_AGE));
    res.cookie('refreshToken', result.refreshToken, buildCookieOptions(REFRESH_MAX_AGE));

    return ApiResponse.success({ user: result.user });
  }

  // ─── Refresh ──────────────────────────────────────────────────────────────────
  // POST /auth/refresh — reads refreshToken cookie, issues new pair
  @Post('refresh')
  @Public()
  @UseGuards(AuthGuard('jwt-refresh'))
  @HttpCode(HttpStatus.OK)
  async refresh(
    @CurrentUser() user: JwtUser,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ApiResponse<null>> {
    const tokens = await this.authService.refresh(user);

    res.cookie('accessToken',  tokens.accessToken,  buildCookieOptions(ACCESS_MAX_AGE));
    res.cookie('refreshToken', tokens.refreshToken, buildCookieOptions(REFRESH_MAX_AGE));

    return ApiResponse.success(null);
  }

  // ─── Logout ───────────────────────────────────────────────────────────────────
  // POST /auth/logout — clears cookies and revokes refresh token in DB
  @Post('logout')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async logout(
    @CurrentUser() user: JwtUser,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ApiResponse<null>> {
    await this.authService.logout(user.userId);
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');
    return ApiResponse.success(null);
  }

  // ─── Me ───────────────────────────────────────────────────────────────────────
  // GET /auth/me — returns current user from DB
  @Get('me')
  @UseGuards(JwtAuthGuard)
  async me(
    @CurrentUser() user: JwtUser,
  ): Promise<ApiResponse<SafeUser | null>> {
    const safeUser = await this.authService['usersService'].findSafeById(user.userId);
    return ApiResponse.success(safeUser);
  }
}