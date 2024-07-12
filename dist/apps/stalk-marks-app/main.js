/******/ (() => { // webpackBootstrap
/******/ 	"use strict";
/******/ 	var __webpack_modules__ = ({

/***/ "./apps/stalk-marks-app/src/app.controller.ts":
/*!****************************************************!*\
  !*** ./apps/stalk-marks-app/src/app.controller.ts ***!
  \****************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AppController = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const app_service_1 = __webpack_require__(/*! ./app.service */ "./apps/stalk-marks-app/src/app.service.ts");
let AppController = class AppController {
    constructor(appService) {
        this.appService = appService;
    }
    getHello() {
        return this.appService.getHello();
    }
};
__decorate([
    (0, common_1.Get)(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", String)
], AppController.prototype, "getHello", null);
AppController = __decorate([
    (0, common_1.Controller)(),
    __metadata("design:paramtypes", [typeof (_a = typeof app_service_1.AppService !== "undefined" && app_service_1.AppService) === "function" ? _a : Object])
], AppController);
exports.AppController = AppController;


/***/ }),

/***/ "./apps/stalk-marks-app/src/app.module.ts":
/*!************************************************!*\
  !*** ./apps/stalk-marks-app/src/app.module.ts ***!
  \************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AppModule = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const config_1 = __webpack_require__(/*! @nestjs/config */ "@nestjs/config");
const core_1 = __webpack_require__(/*! @nestjs/core */ "@nestjs/core");
const app_controller_1 = __webpack_require__(/*! ./app.controller */ "./apps/stalk-marks-app/src/app.controller.ts");
const app_service_1 = __webpack_require__(/*! ./app.service */ "./apps/stalk-marks-app/src/app.service.ts");
const auth_module_1 = __webpack_require__(/*! ./auth/auth.module */ "./apps/stalk-marks-app/src/auth/auth.module.ts");
const at_guard_1 = __webpack_require__(/*! ./common/guards/at.guard */ "./apps/stalk-marks-app/src/common/guards/at.guard.ts");
const prisma_module_1 = __webpack_require__(/*! ./prisma/prisma.module */ "./apps/stalk-marks-app/src/prisma/prisma.module.ts");
const user_module_1 = __webpack_require__(/*! ./user/user.module */ "./apps/stalk-marks-app/src/user/user.module.ts");
const object_module_1 = __webpack_require__(/*! ./object/object.module */ "./apps/stalk-marks-app/src/object/object.module.ts");
let AppModule = class AppModule {
};
AppModule = __decorate([
    (0, common_1.Module)({
        imports: [
            config_1.ConfigModule.forRoot({ isGlobal: true, envFilePath: '.env' }),
            prisma_module_1.PrismaModule,
            auth_module_1.AuthModule,
            user_module_1.UserModule,
            object_module_1.ObjectModule,
        ],
        controllers: [app_controller_1.AppController],
        providers: [
            app_service_1.AppService,
            {
                provide: core_1.APP_GUARD,
                useClass: at_guard_1.AtGuard,
            },
        ],
    })
], AppModule);
exports.AppModule = AppModule;


/***/ }),

/***/ "./apps/stalk-marks-app/src/app.service.ts":
/*!*************************************************!*\
  !*** ./apps/stalk-marks-app/src/app.service.ts ***!
  \*************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AppService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const config_1 = __webpack_require__(/*! @nestjs/config */ "@nestjs/config");
let AppService = class AppService {
    constructor(config) {
        this.config = config;
    }
    getHello() {
        const host = this.config.get('NEO4J_HOST');
        console.log(host);
        return 'Hello World!';
    }
};
AppService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof config_1.ConfigService !== "undefined" && config_1.ConfigService) === "function" ? _a : Object])
], AppService);
exports.AppService = AppService;


/***/ }),

/***/ "./apps/stalk-marks-app/src/auth/auth.controller.ts":
/*!**********************************************************!*\
  !*** ./apps/stalk-marks-app/src/auth/auth.controller.ts ***!
  \**********************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a, _b, _c, _d;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthController = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const decorators_1 = __webpack_require__(/*! ../common/decorators */ "./apps/stalk-marks-app/src/common/decorators/index.ts");
const auth_service_1 = __webpack_require__(/*! ./auth.service */ "./apps/stalk-marks-app/src/auth/auth.service.ts");
const dto_1 = __webpack_require__(/*! ./dto */ "./apps/stalk-marks-app/src/auth/dto/index.ts");
const guards_1 = __webpack_require__(/*! ../common/guards */ "./apps/stalk-marks-app/src/common/guards/index.ts");
const common_2 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const utils_1 = __webpack_require__(/*! ./utils */ "./apps/stalk-marks-app/src/auth/utils/index.ts");
let AuthController = class AuthController {
    constructor(authService) {
        this.authService = authService;
    }
    async signUp(req, data) {
        const signUpData = await this.authService.signUp(data);
        (0, utils_1.setTokensCookie)(req, signUpData.tokens);
        return signUpData;
    }
    async signIn(req, data) {
        const signInData = await this.authService.signIn(data);
        (0, utils_1.setTokensCookie)(req, signInData.tokens);
        return this.authService.signIn(data);
    }
    async refreshToken(req, id, refreshToken) {
        const tokens = await this.authService.refresh(id, refreshToken);
        console.log('refreshToken', id, refreshToken, tokens);
        (0, utils_1.setTokensCookie)(req, tokens);
        return tokens;
    }
    async logOutLocal(id) {
        return this.authService.logOut(id);
    }
};
__decorate([
    (0, common_1.Post)('signUp'),
    (0, decorators_1.Public)(),
    (0, common_1.HttpCode)(common_1.HttpStatus.CREATED),
    __param(0, (0, common_2.Req)()),
    __param(1, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, typeof (_b = typeof dto_1.SignUpData !== "undefined" && dto_1.SignUpData) === "function" ? _b : Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "signUp", null);
__decorate([
    (0, common_1.Post)('signIn'),
    (0, decorators_1.Public)(),
    (0, common_1.HttpCode)(common_1.HttpStatus.CREATED),
    __param(0, (0, common_2.Req)()),
    __param(1, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, typeof (_c = typeof dto_1.SignInData !== "undefined" && dto_1.SignInData) === "function" ? _c : Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "signIn", null);
__decorate([
    (0, common_1.Post)('refresh'),
    (0, decorators_1.Public)(),
    (0, common_1.UseGuards)(guards_1.RtGuard),
    (0, common_1.HttpCode)(common_1.HttpStatus.OK),
    __param(0, (0, common_2.Req)()),
    __param(1, (0, decorators_1.GetCurrentUserId)()),
    __param(2, (0, decorators_1.GetCurrentUser)('refreshToken')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, String, String]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "refreshToken", null);
__decorate([
    (0, common_1.Post)('logOut'),
    (0, common_1.HttpCode)(common_1.HttpStatus.OK),
    __param(0, (0, decorators_1.GetCurrentUserId)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", typeof (_d = typeof Promise !== "undefined" && Promise) === "function" ? _d : Object)
], AuthController.prototype, "logOutLocal", null);
AuthController = __decorate([
    (0, common_1.Controller)('auth'),
    __metadata("design:paramtypes", [typeof (_a = typeof auth_service_1.AuthService !== "undefined" && auth_service_1.AuthService) === "function" ? _a : Object])
], AuthController);
exports.AuthController = AuthController;


/***/ }),

/***/ "./apps/stalk-marks-app/src/auth/auth.module.ts":
/*!******************************************************!*\
  !*** ./apps/stalk-marks-app/src/auth/auth.module.ts ***!
  \******************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthModule = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const jwt_1 = __webpack_require__(/*! @nestjs/jwt */ "@nestjs/jwt");
const prisma_module_1 = __webpack_require__(/*! ../prisma/prisma.module */ "./apps/stalk-marks-app/src/prisma/prisma.module.ts");
const user_module_1 = __webpack_require__(/*! ../user/user.module */ "./apps/stalk-marks-app/src/user/user.module.ts");
const auth_controller_1 = __webpack_require__(/*! ./auth.controller */ "./apps/stalk-marks-app/src/auth/auth.controller.ts");
const auth_resolver_1 = __webpack_require__(/*! ./auth.resolver */ "./apps/stalk-marks-app/src/auth/auth.resolver.ts");
const auth_service_1 = __webpack_require__(/*! ./auth.service */ "./apps/stalk-marks-app/src/auth/auth.service.ts");
const at_strategy_1 = __webpack_require__(/*! ./strategies/at.strategy */ "./apps/stalk-marks-app/src/auth/strategies/at.strategy.ts");
const rt_strategy_1 = __webpack_require__(/*! ./strategies/rt.strategy */ "./apps/stalk-marks-app/src/auth/strategies/rt.strategy.ts");
let AuthModule = class AuthModule {
};
AuthModule = __decorate([
    (0, common_1.Module)({
        imports: [prisma_module_1.PrismaModule, user_module_1.UserModule, jwt_1.JwtModule.register({})],
        providers: [auth_service_1.AuthService, auth_resolver_1.AuthResolver, at_strategy_1.AtStrategy, rt_strategy_1.RtStrategy],
        controllers: [auth_controller_1.AuthController],
    })
], AuthModule);
exports.AuthModule = AuthModule;


/***/ }),

/***/ "./apps/stalk-marks-app/src/auth/auth.resolver.ts":
/*!********************************************************!*\
  !*** ./apps/stalk-marks-app/src/auth/auth.resolver.ts ***!
  \********************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthResolver = void 0;
const graphql_1 = __webpack_require__(/*! @nestjs/graphql */ "@nestjs/graphql");
let AuthResolver = class AuthResolver {
};
AuthResolver = __decorate([
    (0, graphql_1.Resolver)()
], AuthResolver);
exports.AuthResolver = AuthResolver;


/***/ }),

/***/ "./apps/stalk-marks-app/src/auth/auth.service.ts":
/*!*******************************************************!*\
  !*** ./apps/stalk-marks-app/src/auth/auth.service.ts ***!
  \*******************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __rest = (this && this.__rest) || function (s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
};
var _a, _b, _c, _d;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const config_1 = __webpack_require__(/*! @nestjs/config */ "@nestjs/config");
const jwt_1 = __webpack_require__(/*! @nestjs/jwt */ "@nestjs/jwt");
const library_1 = __webpack_require__(/*! @prisma/client/runtime/library */ "@prisma/client/runtime/library");
const argon = __webpack_require__(/*! argon2 */ "argon2");
const prisma_service_1 = __webpack_require__(/*! ../prisma/prisma.service */ "./apps/stalk-marks-app/src/prisma/prisma.service.ts");
const user_service_1 = __webpack_require__(/*! ../user/user.service */ "./apps/stalk-marks-app/src/user/user.service.ts");
let AuthService = class AuthService {
    constructor(config, prisma, userService, jwtService) {
        this.config = config;
        this.prisma = prisma;
        this.userService = userService;
        this.jwtService = jwtService;
    }
    async signUp(data) {
        const { userName, email, password } = data, payload = __rest(data, ["userName", "email", "password"]);
        const checkUser = this.userService.isUniqueUsername(userName);
        if (checkUser) {
            const hashPassword = await argon.hash(data.password);
            const newUser = await this.userService
                .create({
                userName,
                email,
                hashPassword,
            })
                .catch((e) => {
                if (e instanceof library_1.PrismaClientKnownRequestError) {
                    if (e.code === 'P2002') {
                        throw new common_1.ForbiddenException(`пользователь с email или username уже существует`);
                    }
                }
                throw e;
            });
            const tokens = await this.createTokens(newUser.id, userName);
            await this.updateRefreshToken(newUser.id, tokens.refreshToken);
            return { user: { userName: newUser.userName, email: newUser.email }, tokens };
        }
        else {
            throw new common_1.HttpException(`Пользователь уже существует с такими данными: ${userName}`, common_1.HttpStatus.CONFLICT);
        }
    }
    async signIn(data) {
        const user = await this.prisma.user.findFirst({
            where: {
                userName: data.userName,
            },
        });
        if (!user)
            throw new common_1.HttpException('Неверный логин или пароль', common_1.HttpStatus.FORBIDDEN);
        const isPasswordValid = await argon.verify(user.hashPassword, data.password);
        if (!isPasswordValid)
            throw new common_1.HttpException('Неверный пароль', common_1.HttpStatus.FORBIDDEN);
        const tokens = await this.createTokens(user.id, user.userName);
        await this.updateRefreshToken(user.id, tokens.refreshToken);
        return { user: { userName: user.userName, email: user.email }, tokens };
    }
    async logOut(id) {
        return true;
    }
    async refresh(id, rt) {
        const user = await this.prisma.user.findUnique({
            where: {
                id,
            },
        });
        if (!user || !user.hashRefreshToken)
            throw new common_1.ForbiddenException('Access Denied');
        const rtMatches = await argon.verify(user.hashRefreshToken, rt);
        if (!rtMatches)
            throw new common_1.ForbiddenException('Access Denied');
        const tokens = await this.createTokens(user.id, user.email);
        await this.updateRefreshToken(user.id, tokens.refreshToken);
        return tokens;
    }
    async verify() { }
    async createTokens(id, userName) {
        const jwtPayload = {
            sub: id,
            userName,
        };
        const [accessToken, refreshToken] = await Promise.all([
            this.jwtService.signAsync(jwtPayload, {
                expiresIn: '7d',
                secret: this.config.get('AT_SECRET'),
            }),
            this.jwtService.signAsync(jwtPayload, {
                expiresIn: '30d',
                secret: this.config.get('RT_SECRET'),
            }),
        ]);
        return { accessToken, refreshToken };
    }
    async updateRefreshToken(uid, refreshToken) {
        const hashRefreshToken = await argon.hash(refreshToken);
        await this.prisma.user.update({
            where: {
                id: uid,
            },
            data: {
                hashRefreshToken,
            },
        });
    }
};
AuthService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof config_1.ConfigService !== "undefined" && config_1.ConfigService) === "function" ? _a : Object, typeof (_b = typeof prisma_service_1.PrismaService !== "undefined" && prisma_service_1.PrismaService) === "function" ? _b : Object, typeof (_c = typeof user_service_1.UserService !== "undefined" && user_service_1.UserService) === "function" ? _c : Object, typeof (_d = typeof jwt_1.JwtService !== "undefined" && jwt_1.JwtService) === "function" ? _d : Object])
], AuthService);
exports.AuthService = AuthService;


/***/ }),

/***/ "./apps/stalk-marks-app/src/auth/dto/index.ts":
/*!****************************************************!*\
  !*** ./apps/stalk-marks-app/src/auth/dto/index.ts ***!
  \****************************************************/
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));


/***/ }),

/***/ "./apps/stalk-marks-app/src/auth/strategies/at.strategy.ts":
/*!*****************************************************************!*\
  !*** ./apps/stalk-marks-app/src/auth/strategies/at.strategy.ts ***!
  \*****************************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AtStrategy = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const passport_1 = __webpack_require__(/*! @nestjs/passport */ "@nestjs/passport");
const passport_jwt_1 = __webpack_require__(/*! passport-jwt */ "passport-jwt");
const config_1 = __webpack_require__(/*! @nestjs/config */ "@nestjs/config");
let AtStrategy = class AtStrategy extends (0, passport_1.PassportStrategy)(passport_jwt_1.Strategy, 'jwt') {
    constructor(config) {
        super({
            jwtFromRequest: passport_jwt_1.ExtractJwt.fromExtractors([
                passport_jwt_1.ExtractJwt.fromAuthHeaderAsBearerToken(),
            ]),
            secretOrKey: config.get('AT_SECRET'),
        });
    }
    async validate(payload) {
        return payload;
    }
    static extractJWT(req) {
        const cookies = req.cookies;
        console.log('AtStrategy');
        if (cookies) {
            if (!(cookies === null || cookies === void 0 ? void 0 : cookies.accessToken) && (cookies === null || cookies === void 0 ? void 0 : cookies.refreshToken)) {
            }
            return cookies === null || cookies === void 0 ? void 0 : cookies.accessToken;
        }
        return null;
    }
};
AtStrategy = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof config_1.ConfigService !== "undefined" && config_1.ConfigService) === "function" ? _a : Object])
], AtStrategy);
exports.AtStrategy = AtStrategy;


/***/ }),

/***/ "./apps/stalk-marks-app/src/auth/strategies/rt.strategy.ts":
/*!*****************************************************************!*\
  !*** ./apps/stalk-marks-app/src/auth/strategies/rt.strategy.ts ***!
  \*****************************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.RtStrategy = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const config_1 = __webpack_require__(/*! @nestjs/config */ "@nestjs/config");
const passport_1 = __webpack_require__(/*! @nestjs/passport */ "@nestjs/passport");
const passport_jwt_1 = __webpack_require__(/*! passport-jwt */ "passport-jwt");
let RtStrategy = class RtStrategy extends (0, passport_1.PassportStrategy)(passport_jwt_1.Strategy, 'jwt-refresh') {
    constructor(config) {
        super({
            jwtFromRequest: passport_jwt_1.ExtractJwt.fromExtractors([
                passport_jwt_1.ExtractJwt.fromAuthHeaderAsBearerToken(),
            ]),
            ignoreExpiration: false,
            passReqToCallback: true,
            secretOrKey: config.get('RT_SECRET'),
        });
    }
    async validate(req, payload) {
        console.log('RtStrategy');
        const refreshToken = req === null || req === void 0 ? void 0 : req.get('authorization').replace('Bearer', '').trim();
        if (!refreshToken)
            throw new common_1.ForbiddenException('Refresh token malformed');
        return Object.assign(Object.assign({}, payload), { refreshToken });
    }
    static extractJWT(req) {
        const cookies = req.cookies;
        console.log('RtStrategy', cookies);
        if (cookies)
            return cookies === null || cookies === void 0 ? void 0 : cookies.refresh_token;
        return null;
    }
};
RtStrategy = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof config_1.ConfigService !== "undefined" && config_1.ConfigService) === "function" ? _a : Object])
], RtStrategy);
exports.RtStrategy = RtStrategy;


/***/ }),

/***/ "./apps/stalk-marks-app/src/auth/utils/index.ts":
/*!******************************************************!*\
  !*** ./apps/stalk-marks-app/src/auth/utils/index.ts ***!
  \******************************************************/
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.setTokensCookie = void 0;
const setTokensCookie = (req, tokens) => {
    req.res.cookie("accessToken", `${tokens.accessToken}`, {
        httpOnly: true,
        maxAge: 50000
    });
    req.res.cookie("refreshToken", `${tokens.refreshToken}`, {
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 24 * 30,
    });
};
exports.setTokensCookie = setTokensCookie;


/***/ }),

/***/ "./apps/stalk-marks-app/src/common/decorators/cookies.decorator.ts":
/*!*************************************************************************!*\
  !*** ./apps/stalk-marks-app/src/common/decorators/cookies.decorator.ts ***!
  \*************************************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.Cookies = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const graphql_1 = __webpack_require__(/*! @nestjs/graphql */ "@nestjs/graphql");
exports.Cookies = (0, common_1.createParamDecorator)((data, ctx) => {
    var _a, _b;
    if (ctx.getType() === "http") {
        const request = ctx.switchToHttp().getRequest();
        return data ? (_a = request === null || request === void 0 ? void 0 : request.cookies) === null || _a === void 0 ? void 0 : _a[data] : request === null || request === void 0 ? void 0 : request.cookies;
    }
    const ctxGql = graphql_1.GqlExecutionContext.create(ctx);
    const req = ctxGql.getContext().req;
    return data ? (_b = req.cookies) === null || _b === void 0 ? void 0 : _b[data] : req.cookies;
});


/***/ }),

/***/ "./apps/stalk-marks-app/src/common/decorators/get-current-user-id.decorator.ts":
/*!*************************************************************************************!*\
  !*** ./apps/stalk-marks-app/src/common/decorators/get-current-user-id.decorator.ts ***!
  \*************************************************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.GetCurrentUserId = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const graphql_1 = __webpack_require__(/*! @nestjs/graphql */ "@nestjs/graphql");
exports.GetCurrentUserId = (0, common_1.createParamDecorator)((_, ctx) => {
    if (ctx.getType() === 'http') {
        const request = ctx.switchToHttp().getRequest();
        const user = request.user;
        return user.sub;
    }
    const ctxGql = graphql_1.GqlExecutionContext.create(ctx);
    const user = ctxGql.getContext().req.user;
    console.log('GetCurrentUserId user', user);
    if (!user)
        return null;
    return user.sub;
});


/***/ }),

/***/ "./apps/stalk-marks-app/src/common/decorators/get-current-user.decorator.ts":
/*!**********************************************************************************!*\
  !*** ./apps/stalk-marks-app/src/common/decorators/get-current-user.decorator.ts ***!
  \**********************************************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.GetCurrentUser = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const graphql_1 = __webpack_require__(/*! @nestjs/graphql */ "@nestjs/graphql");
exports.GetCurrentUser = (0, common_1.createParamDecorator)((field, ctx) => {
    var _a;
    if (ctx.getType() === 'http') {
        const req = ctx.switchToHttp().getRequest();
        if (!field)
            return req.user;
        return req.user[field];
    }
    const ctxGql = graphql_1.GqlExecutionContext.create(ctx);
    const user = (_a = ctxGql.getContext().req) === null || _a === void 0 ? void 0 : _a.user;
    if (!user)
        return null;
    return user[field];
});


/***/ }),

/***/ "./apps/stalk-marks-app/src/common/decorators/index.ts":
/*!*************************************************************!*\
  !*** ./apps/stalk-marks-app/src/common/decorators/index.ts ***!
  \*************************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
__exportStar(__webpack_require__(/*! ./get-current-user-id.decorator */ "./apps/stalk-marks-app/src/common/decorators/get-current-user-id.decorator.ts"), exports);
__exportStar(__webpack_require__(/*! ./get-current-user.decorator */ "./apps/stalk-marks-app/src/common/decorators/get-current-user.decorator.ts"), exports);
__exportStar(__webpack_require__(/*! ./public.decorator */ "./apps/stalk-marks-app/src/common/decorators/public.decorator.ts"), exports);
__exportStar(__webpack_require__(/*! ./cookies.decorator */ "./apps/stalk-marks-app/src/common/decorators/cookies.decorator.ts"), exports);


/***/ }),

/***/ "./apps/stalk-marks-app/src/common/decorators/public.decorator.ts":
/*!************************************************************************!*\
  !*** ./apps/stalk-marks-app/src/common/decorators/public.decorator.ts ***!
  \************************************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.Public = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const Public = () => (0, common_1.SetMetadata)('isPublic', true);
exports.Public = Public;


/***/ }),

/***/ "./apps/stalk-marks-app/src/common/guards/at.guard.ts":
/*!************************************************************!*\
  !*** ./apps/stalk-marks-app/src/common/guards/at.guard.ts ***!
  \************************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AtGuard = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const core_1 = __webpack_require__(/*! @nestjs/core */ "@nestjs/core");
const graphql_1 = __webpack_require__(/*! @nestjs/graphql */ "@nestjs/graphql");
const passport_1 = __webpack_require__(/*! @nestjs/passport */ "@nestjs/passport");
let AtGuard = class AtGuard extends (0, passport_1.AuthGuard)('jwt') {
    constructor(reflector) {
        super();
        this.reflector = reflector;
    }
    getRequest(ctx) {
        if (ctx.getType() === 'http') {
            const request = ctx.switchToHttp().getRequest();
            return request;
        }
        else {
            console.log('gql');
            const ctxGql = graphql_1.GqlExecutionContext.create(ctx);
            console.log(ctxGql.getContext().req.user);
            return ctxGql.getContext().req;
        }
    }
    canActivate(ctx) {
        const isPublic = this.reflector.getAllAndOverride('isPublic', [
            ctx.getHandler(),
            ctx.getClass(),
        ]);
        return isPublic ? true : super.canActivate(ctx);
    }
};
AtGuard = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof core_1.Reflector !== "undefined" && core_1.Reflector) === "function" ? _a : Object])
], AtGuard);
exports.AtGuard = AtGuard;


/***/ }),

/***/ "./apps/stalk-marks-app/src/common/guards/index.ts":
/*!*********************************************************!*\
  !*** ./apps/stalk-marks-app/src/common/guards/index.ts ***!
  \*********************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
__exportStar(__webpack_require__(/*! ./at.guard */ "./apps/stalk-marks-app/src/common/guards/at.guard.ts"), exports);
__exportStar(__webpack_require__(/*! ./rt.guard */ "./apps/stalk-marks-app/src/common/guards/rt.guard.ts"), exports);


/***/ }),

/***/ "./apps/stalk-marks-app/src/common/guards/rt.guard.ts":
/*!************************************************************!*\
  !*** ./apps/stalk-marks-app/src/common/guards/rt.guard.ts ***!
  \************************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.RtGuard = void 0;
const passport_1 = __webpack_require__(/*! @nestjs/passport */ "@nestjs/passport");
const graphql_1 = __webpack_require__(/*! @nestjs/graphql */ "@nestjs/graphql");
class RtGuard extends (0, passport_1.AuthGuard)('jwt-refresh') {
    constructor() {
        super();
    }
    getRequest(context) {
        if (context.getType() === 'http') {
            return context.switchToHttp().getRequest();
        }
        const ctx = graphql_1.GqlExecutionContext.create(context);
        return ctx.getContext().req;
    }
}
exports.RtGuard = RtGuard;


/***/ }),

/***/ "./apps/stalk-marks-app/src/object/dto/index.ts":
/*!******************************************************!*\
  !*** ./apps/stalk-marks-app/src/object/dto/index.ts ***!
  \******************************************************/
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));


/***/ }),

/***/ "./apps/stalk-marks-app/src/object/object.controller.ts":
/*!**************************************************************!*\
  !*** ./apps/stalk-marks-app/src/object/object.controller.ts ***!
  \**************************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ObjectController = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const index_1 = __webpack_require__(/*! ./dto/index */ "./apps/stalk-marks-app/src/object/dto/index.ts");
const object_service_1 = __webpack_require__(/*! ./object.service */ "./apps/stalk-marks-app/src/object/object.service.ts");
const decorators_1 = __webpack_require__(/*! ../common/decorators */ "./apps/stalk-marks-app/src/common/decorators/index.ts");
let ObjectController = class ObjectController {
    constructor(objectService) {
        this.objectService = objectService;
    }
    async create(data) {
    }
    test() {
        return this.objectService.test();
    }
};
__decorate([
    (0, common_1.Post)('create'),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_b = typeof index_1.CreateObjectDto !== "undefined" && index_1.CreateObjectDto) === "function" ? _b : Object]),
    __metadata("design:returntype", Promise)
], ObjectController.prototype, "create", null);
__decorate([
    (0, common_1.Get)('test'),
    (0, decorators_1.Public)(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", void 0)
], ObjectController.prototype, "test", null);
ObjectController = __decorate([
    (0, common_1.Controller)('object'),
    __metadata("design:paramtypes", [typeof (_a = typeof object_service_1.ObjectService !== "undefined" && object_service_1.ObjectService) === "function" ? _a : Object])
], ObjectController);
exports.ObjectController = ObjectController;


/***/ }),

/***/ "./apps/stalk-marks-app/src/object/object.module.ts":
/*!**********************************************************!*\
  !*** ./apps/stalk-marks-app/src/object/object.module.ts ***!
  \**********************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ObjectModule = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const object_controller_1 = __webpack_require__(/*! ./object.controller */ "./apps/stalk-marks-app/src/object/object.controller.ts");
const object_service_1 = __webpack_require__(/*! ./object.service */ "./apps/stalk-marks-app/src/object/object.service.ts");
let ObjectModule = class ObjectModule {
};
ObjectModule = __decorate([
    (0, common_1.Module)({
        controllers: [object_controller_1.ObjectController],
        providers: [object_service_1.ObjectService],
        exports: [object_service_1.ObjectService],
    })
], ObjectModule);
exports.ObjectModule = ObjectModule;


/***/ }),

/***/ "./apps/stalk-marks-app/src/object/object.service.ts":
/*!***********************************************************!*\
  !*** ./apps/stalk-marks-app/src/object/object.service.ts ***!
  \***********************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ObjectService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
let ObjectService = class ObjectService {
    constructor() { }
    async test() {
        return 'test';
    }
};
ObjectService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [])
], ObjectService);
exports.ObjectService = ObjectService;


/***/ }),

/***/ "./apps/stalk-marks-app/src/prisma/prisma.module.ts":
/*!**********************************************************!*\
  !*** ./apps/stalk-marks-app/src/prisma/prisma.module.ts ***!
  \**********************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.PrismaModule = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const prisma_service_1 = __webpack_require__(/*! ./prisma.service */ "./apps/stalk-marks-app/src/prisma/prisma.service.ts");
let PrismaModule = class PrismaModule {
};
PrismaModule = __decorate([
    (0, common_1.Module)({
        providers: [prisma_service_1.PrismaService],
        exports: [prisma_service_1.PrismaService],
    })
], PrismaModule);
exports.PrismaModule = PrismaModule;


/***/ }),

/***/ "./apps/stalk-marks-app/src/prisma/prisma.service.ts":
/*!***********************************************************!*\
  !*** ./apps/stalk-marks-app/src/prisma/prisma.service.ts ***!
  \***********************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.PrismaService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const client_1 = __webpack_require__(/*! @prisma/client */ "@prisma/client");
let PrismaService = class PrismaService extends client_1.PrismaClient {
    constructor() {
        super({
            datasources: {
                db: {
                    url: process.env.DATABASE_URL,
                },
            },
        });
    }
    async onModuleDestroy() {
        await this.$disconnect();
    }
    async onModuleInit() {
        await this.$connect();
    }
};
PrismaService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [])
], PrismaService);
exports.PrismaService = PrismaService;


/***/ }),

/***/ "./apps/stalk-marks-app/src/user/user.module.ts":
/*!******************************************************!*\
  !*** ./apps/stalk-marks-app/src/user/user.module.ts ***!
  \******************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UserModule = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const prisma_module_1 = __webpack_require__(/*! ../prisma/prisma.module */ "./apps/stalk-marks-app/src/prisma/prisma.module.ts");
const user_resolver_1 = __webpack_require__(/*! ./user.resolver */ "./apps/stalk-marks-app/src/user/user.resolver.ts");
const user_service_1 = __webpack_require__(/*! ./user.service */ "./apps/stalk-marks-app/src/user/user.service.ts");
let UserModule = class UserModule {
};
UserModule = __decorate([
    (0, common_1.Module)({
        imports: [prisma_module_1.PrismaModule],
        providers: [user_service_1.UserService, user_resolver_1.UserResolver],
        exports: [user_service_1.UserService],
    })
], UserModule);
exports.UserModule = UserModule;


/***/ }),

/***/ "./apps/stalk-marks-app/src/user/user.resolver.ts":
/*!********************************************************!*\
  !*** ./apps/stalk-marks-app/src/user/user.resolver.ts ***!
  \********************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UserResolver = void 0;
const graphql_1 = __webpack_require__(/*! @nestjs/graphql */ "@nestjs/graphql");
let UserResolver = class UserResolver {
};
UserResolver = __decorate([
    (0, graphql_1.Resolver)()
], UserResolver);
exports.UserResolver = UserResolver;


/***/ }),

/***/ "./apps/stalk-marks-app/src/user/user.service.ts":
/*!*******************************************************!*\
  !*** ./apps/stalk-marks-app/src/user/user.service.ts ***!
  \*******************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UserService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const prisma_service_1 = __webpack_require__(/*! ../prisma/prisma.service */ "./apps/stalk-marks-app/src/prisma/prisma.service.ts");
let UserService = class UserService {
    constructor(prisma) {
        this.prisma = prisma;
    }
    async create(data) {
        return this.prisma.user.create({ data });
    }
    async isUniqueUsername(userName) {
        const user = await this.prisma.user.findFirst({
            where: {
                userName,
            },
        });
        return !user;
    }
    async isUniqueEmail(email) {
        const user = await this.prisma.user.findFirst({
            where: {
                email,
            },
        });
        return !user;
    }
};
UserService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof prisma_service_1.PrismaService !== "undefined" && prisma_service_1.PrismaService) === "function" ? _a : Object])
], UserService);
exports.UserService = UserService;


/***/ }),

/***/ "@nestjs/common":
/*!*********************************!*\
  !*** external "@nestjs/common" ***!
  \*********************************/
/***/ ((module) => {

module.exports = require("@nestjs/common");

/***/ }),

/***/ "@nestjs/config":
/*!*********************************!*\
  !*** external "@nestjs/config" ***!
  \*********************************/
/***/ ((module) => {

module.exports = require("@nestjs/config");

/***/ }),

/***/ "@nestjs/core":
/*!*******************************!*\
  !*** external "@nestjs/core" ***!
  \*******************************/
/***/ ((module) => {

module.exports = require("@nestjs/core");

/***/ }),

/***/ "@nestjs/graphql":
/*!**********************************!*\
  !*** external "@nestjs/graphql" ***!
  \**********************************/
/***/ ((module) => {

module.exports = require("@nestjs/graphql");

/***/ }),

/***/ "@nestjs/jwt":
/*!******************************!*\
  !*** external "@nestjs/jwt" ***!
  \******************************/
/***/ ((module) => {

module.exports = require("@nestjs/jwt");

/***/ }),

/***/ "@nestjs/passport":
/*!***********************************!*\
  !*** external "@nestjs/passport" ***!
  \***********************************/
/***/ ((module) => {

module.exports = require("@nestjs/passport");

/***/ }),

/***/ "@prisma/client":
/*!*********************************!*\
  !*** external "@prisma/client" ***!
  \*********************************/
/***/ ((module) => {

module.exports = require("@prisma/client");

/***/ }),

/***/ "@prisma/client/runtime/library":
/*!*************************************************!*\
  !*** external "@prisma/client/runtime/library" ***!
  \*************************************************/
/***/ ((module) => {

module.exports = require("@prisma/client/runtime/library");

/***/ }),

/***/ "argon2":
/*!*************************!*\
  !*** external "argon2" ***!
  \*************************/
/***/ ((module) => {

module.exports = require("argon2");

/***/ }),

/***/ "passport-jwt":
/*!*******************************!*\
  !*** external "passport-jwt" ***!
  \*******************************/
/***/ ((module) => {

module.exports = require("passport-jwt");

/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
// This entry need to be wrapped in an IIFE because it need to be isolated against other modules in the chunk.
(() => {
var exports = __webpack_exports__;
/*!******************************************!*\
  !*** ./apps/stalk-marks-app/src/main.ts ***!
  \******************************************/

Object.defineProperty(exports, "__esModule", ({ value: true }));
const core_1 = __webpack_require__(/*! @nestjs/core */ "@nestjs/core");
const app_module_1 = __webpack_require__(/*! ./app.module */ "./apps/stalk-marks-app/src/app.module.ts");
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
async function bootstrap() {
    const app = await core_1.NestFactory.create(app_module_1.AppModule);
    app.useGlobalPipes(new common_1.ValidationPipe());
    await app.listen(3030);
}
bootstrap();

})();

/******/ })()
;