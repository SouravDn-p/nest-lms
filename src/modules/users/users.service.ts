import { Injectable, ConflictException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { User, UserDocument } from './schemas/user.schema';
import { CreateUserDto } from './dto/create-user.dto';
import { CreateUserResponse, SafeUser } from './types/user.types';

const SALT_ROUNDS = 12;

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<UserDocument>,
  ) {}

  async getAllUsers(): Promise<SafeUser[]> {
    const users = await this.userModel
      .find()
      .select('firstName lastName email role image createdAt updatedAt')
      .lean<SafeUser[]>();
    return users;
  }

  async create(
    createUserDto: CreateUserDto,
    imagePath: string | null,
  ): Promise<CreateUserResponse> {
    const exists = await this.userModel.findOne({
      email: createUserDto.email.toLowerCase(),
    });
    if (exists) throw new ConflictException('Email already registered');

    const hashedPassword = await bcrypt.hash(
      createUserDto.password,
      SALT_ROUNDS,
    );

    const user = await this.userModel.create({
      ...createUserDto,
      email: createUserDto.email.toLowerCase(),
      password: hashedPassword,
      image: imagePath,
    });

    return {
      _id: user.id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      role: user.role,
    };
  }

  async findByEmail(email: string): Promise<UserDocument | null> {
    return this.userModel
      .findOne({ email: email.toLowerCase() })
      .select('+password')
      .exec();
  }

  async findById(id: string): Promise<UserDocument | null> {
    return this.userModel.findById(id).exec();
  }

  async findSafeById(id: string): Promise<SafeUser | null> {
    const user = await this.userModel.findById(id).exec();
    if (!user) return null;
    return {
      _id: user.id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      role: user.role,
      image: user.image,
    };
  }

  async updateRefreshToken(
    userId: string,
    refreshToken: string | null,
  ): Promise<void> {
    const hashed = refreshToken
      ? await bcrypt.hash(refreshToken, SALT_ROUNDS)
      : null;
    await this.userModel.findByIdAndUpdate(userId, {
      hashedRefreshToken: hashed,
    });
  }

  async validateRefreshToken(
    userId: string,
    refreshToken: string,
  ): Promise<boolean> {
    const user = await this.userModel
      .findById(userId)
      .select('+hashedRefreshToken')
      .exec();
    if (!user?.hashedRefreshToken) return false;
    return bcrypt.compare(refreshToken, user.hashedRefreshToken);
  }
}
