import { UserRole } from "src/modules/users/schemas/user.schema";

export interface JwtPayload {
  sub: string;
  email: string;
  role: UserRole;
}

export interface JwtUser {
  userId: string;
  email: string;
  role: UserRole;
}
