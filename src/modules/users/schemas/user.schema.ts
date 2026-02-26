import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type UserDocument = User & Document;

export enum UserRole {
  ADMIN = 'admin',
  USER  = 'user',
}

@Schema({ timestamps: true })
export class User {
  @Prop({ required: true, trim: true })
  firstName!: string;

  @Prop({ required: true, trim: true })
  lastName!: string;

  @Prop({ required: true, unique: true, lowercase: true, trim: true })
  email!: string;

  @Prop({ required: true, select: false })
  password!: string;

  @Prop({ type: String, default: null })
  image!: string | null;

  @Prop({ type: String, enum: UserRole, default: UserRole.USER })
  role!: UserRole;

  @Prop({ type: String, default: null, select: false })
  hashedRefreshToken!: string | null;
}

export const UserSchema = SchemaFactory.createForClass(User);