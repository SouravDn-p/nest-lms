import {
  IsEmail,
  IsEnum,
  IsOptional,
  IsString,
  MaxLength,
  MinLength,
} from 'class-validator';
import { UserRole } from '../schemas/user.schema';

export class CreateUserDto {
  @IsString()
  @MinLength(2)
  @MaxLength(60)
  firstName!: string;

  @IsString()
  @MinLength(2)
  @MaxLength(60)
  lastName!: string;

  @IsEmail()
  email!: string;

  @IsString()
  @MinLength(8, { message: 'Password must be at least 8 characters' })
  @MaxLength(100)
  password!: string;

  @IsOptional()
  @IsEnum(UserRole)
  role?: UserRole;
}