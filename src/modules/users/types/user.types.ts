import { UserRole } from '../schemas/user.schema';

export interface CreateUserResponse {
  _id: string;
  firstName: string;
  lastName: string;
  email: string;
  role: UserRole;
}

export interface SafeUser {
  _id: string;
  firstName: string;
  lastName: string;
  email: string;
  role: UserRole;
  image: string | null;
}

export interface UserCredentials {
  email: string;
  password: string;
}
