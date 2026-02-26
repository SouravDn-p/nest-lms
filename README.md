# Complete NestJS Project Guide — Beginner to Production

<p align="center">
  <a href="http://nestjs.com/" target="blank"><img src="https://nestjs.com/img/logo-small.svg" width="120" alt="Nest Logo" /></a>
</p>

[circleci-image]: https://img.shields.io/circleci/build/github/nestjs/nest/master?token=abc123def456
[circleci-url]: https://circleci.com/gh/nestjs/nest

---

## Table of Contents

1. [Entry Point — main.ts](#1-entry-point--maints)
2. [AppModule — app.module.ts](#2-appmodule--appmodulets)
3. [Configuration — app.config.ts & jwt.config.ts](#3-configuration)
4. [User Schema & Types](#4-user-schema--types)
5. [User DTOs](#5-user-dtos)
6. [UsersService (with fixes)](#6-usersservice-with-fixes)
7. [UsersModule & UsersController (with fixes)](#7-usersmodule--userscontroller-with-fixes)
8. [AuthService](#8-authservice)
9. [JWT Strategies — jwt.strategy.ts & refresh.strategy.ts](#9-jwt-strategies)
10. [AuthController](#10-authcontroller)
11. [AuthModule](#11-authmodule)
12. [Guards — JwtAuthGuard & RolesGuard](#12-guards)
13. [Decorators — @Public, @Roles, @CurrentUser](#13-decorators)
14. [Global Exception Filter](#14-global-exception-filter)
15. [Response Interceptor](#15-response-interceptor)
16. [Global Types — ApiResponse](#16-global-types--apiresponse)
17. [Projects Module (NEW)](#17-projects-module-new)
18. [ImgBB Image Upload Service (NEW)](#18-imgbb-image-upload-service-new)
19. [How Auto-Refresh Works](#19-how-auto-refresh-works)
20. [Security Checklist](#20-security-checklist)
21. [Environment Variables (.env)](#21-environment-variables)

---

## 1. Entry Point — main.ts

```typescript
async function bootstrap(): Promise<void> {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
  ...
}
```

**What this file does:** This is the very first file Node.js runs. `bootstrap()` starts your entire NestJS application.

### Line by Line

**`NestFactory.create<NestExpressApplication>(AppModule)`**
Creates the NestJS app using Express under the hood (the default). The generic `<NestExpressApplication>` gives you Express-specific methods.

**`app.enableCors({ origin: [...], credentials: true })`**
Allows your frontend (running on localhost:3000 or :3001) to call your API. `credentials: true` is required when using cookies — without it, the browser will refuse to send cookies cross-origin.

**`app.use(cookieParser())`**
This is Express middleware that reads the `Cookie` header and parses it into `req.cookies`. Without this, `request.cookies.accessToken` would always be `undefined`, and your JWT strategy would never see the token.

**`app.useGlobalPipes(new ValidationPipe(...))`**
A pipe runs before your route handler receives the data.

- `whitelist: true` — strips any fields from the request body that are not in the DTO
- `forbidNonWhitelisted: true` — throws an error if extra fields are sent
- `transform: true` — converts incoming strings to the correct types (e.g., `"3"` → `3`)

**`app.useGlobalFilters(new GlobalExceptionFilter())`**
Any unhandled error in any controller/service will be caught here and formatted as a consistent JSON error response.

**`app.useGlobalInterceptors(new ResponseInterceptor())`**
Wraps every successful response in your `ApiResponse` envelope automatically.

---

## 2. AppModule — app.module.ts

```typescript
@Module({
  imports: [...],
  providers: [
    { provide: APP_GUARD, useClass: JwtAuthGuard },
    { provide: APP_GUARD, useClass: RolesGuard },
  ],
})
export class AppModule {}
```

**What this file does:** The root module that bootstraps the whole application. Think of it as the "main file" of your module system.

### Key Concepts

**`ConfigModule.forRoot({ isGlobal: true, load: [appConfig, jwtConfig] })`**
Makes the ConfigService available everywhere without importing it per module. `load` registers typed config namespaces like `config.get('jwt.accessSecret')`.

**`MongooseModule.forRootAsync(...)`**
`forRootAsync` means "wait until ConfigService is ready, then connect". This is better than `forRoot` because it ensures env variables are loaded first.

**`APP_GUARD` Providers**
These are global guards applied to EVERY route. The order matters:

1. `JwtAuthGuard` runs first — validates the JWT access token
2. `RolesGuard` runs second — checks if the user has the required role

Using `APP_GUARD` is cleaner than putting `@UseGuards()` on every single controller.

---

## 3. Configuration

### app.config.ts

```typescript
export default registerAs<AppConfig>(
  'app',
  (): AppConfig => ({
    port: Number(process.env.PORT) || 5000,
    env: process.env.NODE_ENV || 'development',
  }),
);
```

`registerAs('app', ...)` creates a config **namespace**. You access it with `configService.get<AppConfig>('app')`. This pattern keeps related config grouped and fully typed.

### jwt.config.ts

```typescript
export default registerAs<JwtConfig>(
  'jwt',
  (): JwtConfig => ({
    accessSecret: process.env.JWT_ACCESS_SECRET ?? 'fallback-access-secret',
    refreshSecret: process.env.JWT_REFRESH_SECRET ?? 'fallback-refresh-secret',
    accessExpiresIn: Number(process.env.JWT_ACCESS_EXPIRES_IN) || 900, // 15 min
    refreshExpiresIn: Number(process.env.JWT_REFRESH_EXPIRES_IN) || 604800, // 7 days
  }),
);
```

**Important:** The `accessExpiresIn` is in **seconds** (900 = 15 minutes). The cookie `maxAge` in the controller is in **milliseconds** (so 15 _ 60 _ 1000). These must stay in sync.

---

## 4. User Schema & Types

### user.schema.ts

```typescript
@Schema({ timestamps: true })
export class User {
  @Prop({ required: true, select: false })
  password!: string;

  @Prop({ type: String, default: null, select: false })
  hashedRefreshToken!: string | null;
}
```

**Key design decisions:**

- `select: false` on `password` and `hashedRefreshToken` means these fields are **never returned** in a normal query. You must explicitly opt-in with `.select('+password')`. This prevents accidental password leaks.
- `timestamps: true` automatically adds `createdAt` and `updatedAt` fields to every document.
- `HydratedDocument<User>` is the correct modern type (not the older `User & Document`).

### user.types.ts

These TypeScript interfaces define what you return to the client. `SafeUser` never includes `password` or `hashedRefreshToken` — only the fields safe to expose.

---

## 5. User DTOs

**DTO = Data Transfer Object.** It describes the shape of data coming INTO your API. The class-validator decorators are rules.

```typescript
export class CreateUserDto {
  @IsString()
  @MinLength(2)
  firstName!: string;
  ...
}
```

When `ValidationPipe` processes an incoming request:

1. It tries to instantiate the class using the request body
2. It runs all the `@Is*` validators
3. If validation fails, it throws a `400 Bad Request` with detailed error messages
4. If validation passes, the clean, typed DTO object reaches your controller

---

## 6. UsersService (with fixes)

**⚠️ Bug Fix Applied:** Your `getAllUsers` and `findSafeById` had no return type. Added proper types.

```typescript
// BEFORE (no return type — TypeScript can't help you)
async getAllUsers() { ... }

// AFTER (explicit, safe)
async getAllUsers(): Promise<SafeUser[]> {
  const users = await this.userModel.find().exec();
  return users.map(u => this.toSafeUser(u)); // never return raw documents!
}
```

**Key methods explained:**

**`create()`** — Hashes the password with bcrypt (SALT_ROUNDS=12 means the hash takes ~250ms on a modern CPU — expensive enough to deter brute-force, fast enough for users) then saves to MongoDB.

**`findByEmail()`** — `.select('+password')` explicitly fetches the password field (since `select: false` hides it normally). Needed for login.

**`updateRefreshToken()`** — Stores a **hashed** refresh token, not the raw token. Why? If your database is compromised, attackers cannot use the hashed tokens directly.

**`validateRefreshToken()`** — Uses `bcrypt.compare` to check if the incoming raw refresh token matches the stored hash.

---

## 7. UsersModule & UsersController (with fixes)

### UsersController — Fixed Version

```typescript
// BEFORE (no return type)
async getUsers() {
  const users = await this.userService.getAllUsers();
  return users;
}

// AFTER (typed, uses SafeUser instead of raw documents)
@Get()
@Public()
async getUsers(): Promise<ApiResponse<SafeUser[]>> {
  const users = await this.userService.getAllUsers();
  return ApiResponse.success(users);
}
```

**Why `@Public()`?** The global `JwtAuthGuard` blocks all routes by default. `@Public()` tells it to skip authentication for this specific route.

### UsersModule

`exports: [UsersService]` is critical — it makes `UsersService` available to any module that imports `UsersModule`. The `AuthModule` needs this to call `usersService.findByEmail()` during login.

---

## 8. AuthService

The heart of your authentication logic.

```typescript
async login(loginDto: LoginDto): Promise<LoginResult> {
  const user = await this.usersService.findByEmail(loginDto.email);
  if (!user) throw new UnauthorizedException('Invalid credentials');

  const passwordMatch = await bcrypt.compare(loginDto.password, user.password);
  if (!passwordMatch) throw new UnauthorizedException('Invalid credentials');
  ...
}
```

**Security note:** Both "user not found" and "wrong password" throw the same `'Invalid credentials'` error message. This is intentional — it prevents **user enumeration** (attackers cannot tell whether an email exists by trying different error messages).

**`generateTokens()`** uses `Promise.all` to sign both JWT tokens in parallel, which is slightly faster than doing them sequentially.

```typescript
async logout(userId: string): Promise<void> {
  await this.usersService.updateRefreshToken(userId, null);
}
```

Logout sets the `hashedRefreshToken` to `null` in the database. Even if someone stole the refresh token cookie before logout, the stored hash is gone so the token becomes permanently invalid.

---

## 9. JWT Strategies

### JwtStrategy (Access Token)

```typescript
jwtFromRequest: ExtractJwt.fromExtractors([
  (request: Request): string | null => {
    const cookies = request.cookies as Record<string, string | undefined>;
    return cookies['accessToken'] ?? null;
  },
]),
```

This is how Passport reads the JWT. Instead of looking in the `Authorization: Bearer` header (the API-client approach), we extract from the `accessToken` **httpOnly cookie**. This is more secure for browser-based apps because JavaScript cannot read httpOnly cookies.

`validate(payload)` is called after the signature is verified. It returns the `JwtUser` object, which NestJS attaches to `request.user`.

### RefreshStrategy (Refresh Token)

```typescript
const options: StrategyOptions = {
  ...
  passReqToCallback: true, // ← passes the full Request to validate()
};

async validate(request: Request, payload: JwtPayload): Promise<JwtUser> {
  const refreshToken = request.cookies['refreshToken'];
  const isValid = await this.usersService.validateRefreshToken(payload.sub, refreshToken);
  if (!isValid) throw new UnauthorizedException('Invalid or expired refresh token');
  ...
}
```

`passReqToCallback: true` allows the `validate` method to receive the raw Request object. This is needed to read the refresh token cookie and compare it against the database hash — a **double validation**. Just having a valid JWT signature isn't enough; the token must also match what's stored in the DB.

---

## 10. AuthController

```typescript
// Cookie constants
const ACCESS_MAX_AGE = 15 * 60 * 1000; // 15 minutes in ms
const REFRESH_MAX_AGE = 7 * 24 * 60 * 60 * 1000; // 7 days in ms
```

### Why HTTP-Only Cookies?

When you call `res.cookie('accessToken', token, { httpOnly: true, ... })`:

- The browser stores the cookie automatically
- The browser sends it automatically on every request to your domain
- **JavaScript can NEVER read it** (`document.cookie` won't see it)
- This eliminates the entire class of XSS token-theft attacks

### Cookie Options

```typescript
function buildCookieOptions(maxAge: number) {
  return {
    httpOnly: true, // JS cannot read this cookie
    secure: process.env.NODE_ENV === 'production', // HTTPS only in prod
    sameSite: 'strict', // cookie is NOT sent on cross-site requests (CSRF protection)
    maxAge,
  };
}
```

- `secure: true` in production ensures the cookie is only sent over HTTPS
- `sameSite: 'strict'` means the cookie won't be sent if the user clicks a link from another site (prevents CSRF attacks)

### `@Res({ passthrough: true })`

Without `passthrough: true`, NestJS hands full control of the response to you, bypassing its own response handling. `passthrough: true` lets you set cookies while still returning a value normally.

### The `me` Endpoint — ⚠️ Code Smell Fix Needed

```typescript
// ORIGINAL — accesses private service property directly (bad practice)
const safeUser = await this.authService['usersService'].findSafeById(user.userId);

// BETTER — expose a proper method in AuthService
async me(userId: string): Promise<SafeUser | null> {
  return this.usersService.findSafeById(userId);
}
```

---

## 11. AuthModule

```typescript
@Module({
  imports: [
    UsersModule,                           // brings in UsersService
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.register({}),                // empty — we pass options per-sign in AuthService
    MulterModule.register({ dest: './uploads/avatars' }),
  ],
  providers: [AuthService, JwtStrategy, RefreshStrategy],
})
```

`JwtModule.register({})` with an empty config is intentional — secrets are passed at sign-time in `AuthService.generateTokens()`, which gives more flexibility (different secrets per token type).

---

## 12. Guards

### JwtAuthGuard

```typescript
@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  canActivate(context: ExecutionContext) {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [...]);
    if (isPublic) return true;           // ← bypass auth for @Public() routes
    return super.canActivate(context);   // ← run Passport JWT validation
  }
}
```

**Flow:**

1. Check if the route/controller has `@Public()` metadata
2. If public → allow through
3. If protected → run Passport's JWT verification (reads cookie, verifies signature, calls `validate()`)
4. If valid → `request.user` is set to the `JwtUser` object
5. If invalid → Passport throws `401 Unauthorized`

### RolesGuard

```typescript
canActivate(context: ExecutionContext): boolean {
  const requiredRoles = this.reflector.getAllAndOverride<UserRole[]>(ROLES_KEY, [...]);
  if (!requiredRoles || requiredRoles.length === 0) return true; // no roles needed

  const user = request.user;
  return requiredRoles.includes(user.role); // user must have one of the required roles
}
```

This runs AFTER `JwtAuthGuard`, so `request.user` is guaranteed to be set. If the user's role isn't in the `requiredRoles` array, they get `403 Forbidden`.

---

## 13. Decorators

### @Public()

```typescript
export const IS_PUBLIC_KEY = 'isPublic';
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
```

`SetMetadata` attaches metadata to a route handler. The `JwtAuthGuard` reads this metadata using `Reflector`.

### @Roles(...roles)

```typescript
export const ROLES_KEY = 'roles';
export const Roles = (...roles: UserRole[]) => SetMetadata(ROLES_KEY, roles);

// Usage:
@Roles(UserRole.ADMIN)
@Post('admin-only')
async adminEndpoint() { ... }
```

### @CurrentUser()

```typescript
export const CurrentUser = createParamDecorator(
  (_data, ctx: ExecutionContext): JwtUser => {
    const request = ctx.switchToHttp().getRequest();
    return request.user; // set by JwtAuthGuard after token validation
  },
);

// Usage in controller:
async me(@CurrentUser() user: JwtUser) { ... }
```

---

## 14. Global Exception Filter

```typescript
@Catch() // catches ALL errors (no argument = catch everything)
export class GlobalExceptionFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost): void {
    ...
    if (exception instanceof HttpException) {
      // NestJS built-in exceptions (BadRequestException, NotFoundException, etc.)
      status = exception.getStatus();
    } else {
      // Unexpected errors (database down, code bugs, etc.)
      this.logger.error(`Unhandled exception: ${String(exception)}`);
      // status stays 500
    }

    response.status(status).json(errorResponse);
  }
}
```

Without this filter, NestJS would return its default error format. With it, every error — whether from your code, a validation pipe, or Mongoose — returns the same `ApiResponse` shape your frontend expects.

---

## 15. Response Interceptor

```typescript
intercept(context, next: CallHandler): Observable<ApiResponse<T>> {
  return next.handle().pipe(
    map((data: T) => {
      if (this.isApiResponse(data)) return data; // already wrapped — pass through

      // Wrap plain return values
      return {
        success: true,
        message: this.getSuccessMessage(statusCode),
        data,
        meta: { statusCode, path, timestamp },
      };
    }),
  );
}
```

The `isApiResponse` check prevents double-wrapping. When your controller returns `ApiResponse.success(data)`, the interceptor detects it's already wrapped and passes it through unchanged.

---

## 16. Global Types — ApiResponse

```typescript
export class ApiResponse<T> {
  static success<T>(data?: T): ApiResponse<T> {
    return new ApiResponse<T>(true, 'success', data);
  }

  static error(message: string): ApiResponse<never> {
    return new ApiResponse<never>(false, message);
  }
}
```

Every API response looks like:

```json
{
  "success": true,
  "message": "success",
  "data": { ... },
  "meta": { "statusCode": 200, "path": "/auth/me", "timestamp": "..." }
}
```

Your frontend always knows exactly where the data is and whether the request succeeded.

---

## 17. Projects Module (NEW)

### File Structure

```
src/modules/projects/
  ├── dto/
  │   ├── create-project.dto.ts
  │   └── update-project.dto.ts
  ├── schemas/
  │   └── project.schema.ts
  ├── types/
  │   └── project.types.ts
  ├── projects.controller.ts
  ├── projects.service.ts
  └── projects.module.ts
```

### Route Access Control

| Route                | Method | Auth Required | Role  |
| -------------------- | ------ | ------------- | ----- |
| GET /projects        | GET    | No            | —     |
| GET /projects/:id    | GET    | No            | —     |
| POST /projects       | POST   | Yes           | ADMIN |
| PATCH /projects/:id  | PATCH  | Yes           | ADMIN |
| DELETE /projects/:id | DELETE | Yes           | ADMIN |

### DTO Fix — @Type(() => Number)

In multipart/form-data, ALL fields arrive as strings. Without `@Type(() => Number)`, `teamMember: "3"` would fail the `@IsNumber()` validator.

```typescript
// In create-project.dto.ts
@Type(() => Number)    // transforms "3" → 3 BEFORE validation runs
@IsNumber()
@Min(1)
teamMember!: number;
```

This requires `transform: true` in ValidationPipe (already set in main.ts) and `@nestjs/class-transformer` (bundled with `@nestjs/common`).

### Add ProjectsModule to AppModule

```typescript
// In app.module.ts — add to imports array:
import { ProjectsModule } from './modules/projects/projects.module';

@Module({
  imports: [
    ...
    ProjectsModule, // ← add this
  ],
})
```

---

## 18. ImgBB Image Upload Service (NEW)

### Why ImgBB?

Instead of storing images on disk (which is lost on server restart) or setting up S3/Cloudinary, ImgBB gives you a free, permanent image hosting URL via a simple REST API.

### Flow

```
Client                    NestJS                   ImgBB
  |                          |                        |
  |-- POST /projects ------> |                        |
  |   (multipart + image)    |                        |
  |                          |-- upload base64 -----> |
  |                          | <-- returns URL ------- |
  |                          |                        |
  |                          | (save URL to MongoDB)  |
  | <-- response with URL -- |                        |
```

### Setup

1. Create account at https://imgbb.com
2. Get API key at https://api.imgbb.com
3. Add to `.env`: `IMGBB_API_KEY=your_key`

### Why `memoryStorage()` instead of `diskStorage()`?

```typescript
// For ImgBB: use memoryStorage() — file is available as file.buffer (raw bytes)
FileInterceptor('image', { storage: memoryStorage() })

// For local disk: use diskStorage() — file is saved and available as file.path
FileInterceptor('image', { storage: diskStorage({...}) })
```

ImgBB's API needs the image as a base64 string. With `memoryStorage()`, you have `file.buffer` which you convert to base64 instantly. With `diskStorage()`, you'd need to read the file back from disk first.

---

## 19. How Auto-Refresh Works

This is the complete auth flow including automatic token refresh:

```
LOGIN:
  POST /auth/login
  → Server verifies credentials
  → Server generates accessToken (15min) + refreshToken (7 days)
  → Both stored as httpOnly cookies
  → hashedRefreshToken saved to MongoDB

AUTHENTICATED REQUEST (accessToken valid):
  Request arrives with accessToken cookie
  → JwtAuthGuard reads cookie
  → Passport verifies JWT signature + expiry
  → request.user is set
  → Request succeeds ✓

AUTHENTICATED REQUEST (accessToken expired):
  Request arrives with expired accessToken cookie
  → JwtAuthGuard → Passport throws 401
  → Frontend intercepts 401 response
  → Frontend calls POST /auth/refresh (refresh cookie is sent automatically)
  → RefreshStrategy reads refreshToken cookie
  → Verifies JWT signature (not expired — 7 day lifetime)
  → Validates against DB hash (double-check)
  → Generates new accessToken + refreshToken pair
  → New cookies set on response
  → Frontend retries original request ✓

LOGOUT:
  POST /auth/logout
  → Clears both cookies from browser
  → Sets hashedRefreshToken = null in MongoDB
  → Even if old refreshToken is stolen, it's now invalid ✓
```

### Frontend Axios Interceptor (Reference)

```typescript
// This handles auto-refresh on the frontend side
axios.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401 && !error.config._retry) {
      error.config._retry = true;
      try {
        await axios.post('/auth/refresh', {}, { withCredentials: true });
        return axios(error.config); // retry original request
      } catch {
        window.location.href = '/login'; // refresh also failed, force re-login
      }
    }
    return Promise.reject(error);
  },
);
```

---

## 20. Security Checklist

| Feature                                         | Status | Where               |
| ----------------------------------------------- | ------ | ------------------- |
| Passwords hashed with bcrypt (12 rounds)        | ✅     | UsersService        |
| Refresh tokens hashed in DB                     | ✅     | UsersService        |
| httpOnly cookies (JS cannot steal tokens)       | ✅     | AuthController      |
| secure: true in production (HTTPS only)         | ✅     | buildCookieOptions  |
| sameSite: strict (CSRF protection)              | ✅     | buildCookieOptions  |
| Input validation on all DTOs                    | ✅     | ValidationPipe      |
| Extra fields stripped from requests             | ✅     | whitelist: true     |
| Passwords/tokens hidden from DB queries         | ✅     | select: false       |
| Role-based access control                       | ✅     | RolesGuard          |
| User enumeration prevention                     | ✅     | AuthService.login   |
| Refresh token rotation (new token each refresh) | ✅     | AuthService.refresh |
| Token invalidation on logout                    | ✅     | DB null on logout   |

---

## 21. Environment Variables

Create a `.env` file in your project root:

```env
# App
PORT=5000
NODE_ENV=development

# MongoDB
MONGODB_URI=mongodb://localhost:27017/your-db-name

# JWT — use long random strings in production
JWT_ACCESS_SECRET=your-super-secret-access-key-here
JWT_REFRESH_SECRET=your-super-secret-refresh-key-here
JWT_ACCESS_EXPIRES_IN=900       # 15 minutes in seconds
JWT_REFRESH_EXPIRES_IN=604800   # 7 days in seconds

# ImgBB (for project image uploads)
IMGBB_API_KEY=your-imgbb-api-key-here
```

**Generate secure secrets:**

```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

---

## Install Required Packages

```bash
# Core packages
npm install @nestjs/common @nestjs/core @nestjs/platform-express
npm install @nestjs/mongoose mongoose
npm install @nestjs/passport @nestjs/jwt passport passport-jwt
npm install @nestjs/config
npm install @nestjs/platform-express @nestjs/mapped-types
npm install cookie-parser bcrypt axios multer

# Types
npm install -D @types/passport-jwt @types/cookie-parser @types/bcrypt @types/multer

# Validation
npm install class-validator class-transformer
```
