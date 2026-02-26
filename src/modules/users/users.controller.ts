import { Controller, Get } from '@nestjs/common';
import { UsersService } from './users.service';
import { Public } from 'src/common/decorators/public.decorator';
import { ApiResponse } from 'src/common/types/global';
import { SafeUser } from './types/user.types';

@Controller('users')
export class UsersController {
  constructor(private readonly userService: UsersService) {}

  @Get()
  @Public()
  async getUsers(): Promise<ApiResponse<SafeUser[]>> {
    const users = await this.userService.getAllUsers();
    return ApiResponse.success(users);
  }
}
