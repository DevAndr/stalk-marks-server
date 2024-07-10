/******/ (() => { // webpackBootstrap
/******/ 	var __webpack_modules__ = ({

/***/ "./node_modules/passport-jwt/lib/auth_header.js":
/*!******************************************************!*\
  !*** ./node_modules/passport-jwt/lib/auth_header.js ***!
  \******************************************************/
/***/ ((module) => {

"use strict";


var re = /(\S+)\s+(\S+)/;



function parseAuthHeader(hdrValue) {
    if (typeof hdrValue !== 'string') {
        return null;
    }
    var matches = hdrValue.match(re);
    return matches && { scheme: matches[1], value: matches[2] };
}



module.exports = {
    parse: parseAuthHeader
};


/***/ }),

/***/ "./node_modules/passport-jwt/lib/extract_jwt.js":
/*!******************************************************!*\
  !*** ./node_modules/passport-jwt/lib/extract_jwt.js ***!
  \******************************************************/
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

"use strict";


var url = __webpack_require__(/*! url */ "url"),
    auth_hdr = __webpack_require__(/*! ./auth_header */ "./node_modules/passport-jwt/lib/auth_header.js");

// Note: express http converts all headers
// to lower case.
var AUTH_HEADER = "authorization",
    LEGACY_AUTH_SCHEME = "JWT", 
    BEARER_AUTH_SCHEME = 'bearer';


var extractors = {};


extractors.fromHeader = function (header_name) {
    return function (request) {
        var token = null;
        if (request.headers[header_name]) {
            token = request.headers[header_name];
        }
        return token;
    };
};



extractors.fromBodyField = function (field_name) {
    return function (request) {
        var token = null;
        if (request.body && Object.prototype.hasOwnProperty.call(request.body, field_name)) {
            token = request.body[field_name];
        }
        return token;
    };
};



extractors.fromUrlQueryParameter = function (param_name) {
    return function (request) {
        var token = null,
            parsed_url = url.parse(request.url, true);
        if (parsed_url.query && Object.prototype.hasOwnProperty.call(parsed_url.query, param_name)) {
            token = parsed_url.query[param_name];
        }
        return token;
    };
};



extractors.fromAuthHeaderWithScheme = function (auth_scheme) {
    var auth_scheme_lower = auth_scheme.toLowerCase();
    return function (request) {

        var token = null;
        if (request.headers[AUTH_HEADER]) {
            var auth_params = auth_hdr.parse(request.headers[AUTH_HEADER]);
            if (auth_params && auth_scheme_lower === auth_params.scheme.toLowerCase()) {
                token = auth_params.value;
            }
        }
        return token;
    };
};



extractors.fromAuthHeaderAsBearerToken = function () {
    return extractors.fromAuthHeaderWithScheme(BEARER_AUTH_SCHEME);
};


extractors.fromExtractors = function(extractors) {
    if (!Array.isArray(extractors)) {
        throw new TypeError('extractors.fromExtractors expects an array')
    }
    
    return function (request) {
        var token = null;
        var index = 0;
        while(!token && index < extractors.length) {
            token = extractors[index].call(this, request);
            index ++;
        }
        return token;
    }
};


/**
 * This extractor mimics the behavior of the v1.*.* extraction logic.
 *
 * This extractor exists only to provide an easy transition from the v1.*.* API to the v2.0.0
 * API.
 *
 * This extractor first checks the auth header, if it doesn't find a token there then it checks the 
 * specified body field and finally the url query parameters.
 * 
 * @param options
 *          authScheme: Expected scheme when JWT can be found in HTTP Authorize header. Default is JWT. 
 *          tokenBodyField: Field in request body containing token. Default is auth_token.
 *          tokenQueryParameterName: Query parameter name containing the token. Default is auth_token.
 */
extractors.versionOneCompatibility = function (options) {
    var authScheme = options.authScheme || LEGACY_AUTH_SCHEME,
        bodyField = options.tokenBodyField || 'auth_token',
        queryParam = options.tokenQueryParameterName || 'auth_token';

    return function (request) {
        var authHeaderExtractor = extractors.fromAuthHeaderWithScheme(authScheme);
        var token =  authHeaderExtractor(request);
        
        if (!token) {
            var bodyExtractor = extractors.fromBodyField(bodyField);
            token = bodyExtractor(request);
        }

        if (!token) {
            var queryExtractor = extractors.fromUrlQueryParameter(queryParam);
            token = queryExtractor(request);
        }

        return token;
    };
}



/**
 * Export the Jwt extraction functions
 */
module.exports = extractors;


/***/ }),

/***/ "./node_modules/passport-jwt/lib/helpers/assign.js":
/*!*********************************************************!*\
  !*** ./node_modules/passport-jwt/lib/helpers/assign.js ***!
  \*********************************************************/
/***/ ((module) => {

// note: This is a polyfill to Object.assign to support old nodejs versions (0.10 / 0.12) where
// Object.assign doesn't exist.
// Source: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/assign
module.exports = function(target, varArgs) {
  if (target == null) { // TypeError if undefined or null
    throw new TypeError('Cannot convert undefined or null to object');
  }

  var to = Object(target);

  for (var index = 1; index < arguments.length; index++) {
    var nextSource = arguments[index];

    if (nextSource != null) { // Skip over if undefined or null
      for (var nextKey in nextSource) {
        // Avoid bugs when hasOwnProperty is shadowed
        if (Object.prototype.hasOwnProperty.call(nextSource, nextKey)) {
          to[nextKey] = nextSource[nextKey];
        }
      }
    }
  }
  return to;
};


/***/ }),

/***/ "./node_modules/passport-jwt/lib/index.js":
/*!************************************************!*\
  !*** ./node_modules/passport-jwt/lib/index.js ***!
  \************************************************/
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

"use strict";


var Strategy = __webpack_require__(/*! ./strategy */ "./node_modules/passport-jwt/lib/strategy.js"),
    ExtractJwt = __webpack_require__(/*! ./extract_jwt.js */ "./node_modules/passport-jwt/lib/extract_jwt.js");


module.exports = {
    Strategy: Strategy,
    ExtractJwt : ExtractJwt
};


/***/ }),

/***/ "./node_modules/passport-jwt/lib/strategy.js":
/*!***************************************************!*\
  !*** ./node_modules/passport-jwt/lib/strategy.js ***!
  \***************************************************/
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

var passport = __webpack_require__(/*! passport-strategy */ "./node_modules/passport-strategy/lib/index.js")
    , auth_hdr = __webpack_require__(/*! ./auth_header */ "./node_modules/passport-jwt/lib/auth_header.js")
    , util = __webpack_require__(/*! util */ "util")
    , url = __webpack_require__(/*! url */ "url")
    , assign = __webpack_require__(/*! ./helpers/assign.js */ "./node_modules/passport-jwt/lib/helpers/assign.js");



/**
 * Strategy constructor
 *
 * @param options
 *          secretOrKey: String or buffer containing the secret or PEM-encoded public key. Required unless secretOrKeyProvider is provided.
 *          secretOrKeyProvider: callback in the format secretOrKeyProvider(request, rawJwtToken, done)`,
 *                               which should call done with a secret or PEM-encoded public key
 *                               (asymmetric) for the given undecoded jwt token string and  request
 *                               combination. done has the signature function done(err, secret).
 *                               REQUIRED unless `secretOrKey` is provided.
 *          jwtFromRequest: (REQUIRED) Function that accepts a request as the only parameter and returns the either JWT as a string or null
 *          issuer: If defined issuer will be verified against this value
 *          audience: If defined audience will be verified against this value
 *          algorithms: List of strings with the names of the allowed algorithms. For instance, ["HS256", "HS384"].
 *          ignoreExpiration: if true do not validate the expiration of the token.
 *          passReqToCallback: If true the verify callback will be called with args (request, jwt_payload, done_callback).
 * @param verify - Verify callback with args (jwt_payload, done_callback) if passReqToCallback is false,
 *                 (request, jwt_payload, done_callback) if true.
 */
function JwtStrategy(options, verify) {

    passport.Strategy.call(this);
    this.name = 'jwt';

    this._secretOrKeyProvider = options.secretOrKeyProvider;

    if (options.secretOrKey) {
        if (this._secretOrKeyProvider) {
          	throw new TypeError('JwtStrategy has been given both a secretOrKey and a secretOrKeyProvider');
        }
        this._secretOrKeyProvider = function (request, rawJwtToken, done) {
            done(null, options.secretOrKey)
        };
    }

    if (!this._secretOrKeyProvider) {
        throw new TypeError('JwtStrategy requires a secret or key');
    }

    this._verify = verify;
    if (!this._verify) {
        throw new TypeError('JwtStrategy requires a verify callback');
    }

    this._jwtFromRequest = options.jwtFromRequest;
    if (!this._jwtFromRequest) {
        throw new TypeError('JwtStrategy requires a function to retrieve jwt from requests (see option jwtFromRequest)');
    }

    this._passReqToCallback = options.passReqToCallback;
    var jsonWebTokenOptions = options.jsonWebTokenOptions || {};
    //for backwards compatibility, still allowing you to pass
    //audience / issuer / algorithms / ignoreExpiration
    //on the options.
    this._verifOpts = assign({}, jsonWebTokenOptions, {
      audience: options.audience,
      issuer: options.issuer,
      algorithms: options.algorithms,
      ignoreExpiration: !!options.ignoreExpiration
    });

}
util.inherits(JwtStrategy, passport.Strategy);



/**
 * Allow for injection of JWT Verifier.
 *
 * This improves testability by allowing tests to cleanly isolate failures in the JWT Verification
 * process from failures in the passport related mechanics of authentication.
 *
 * Note that this should only be replaced in tests.
 */
JwtStrategy.JwtVerifier = __webpack_require__(/*! ./verify_jwt */ "./node_modules/passport-jwt/lib/verify_jwt.js");



/**
 * Authenticate request based on JWT obtained from header or post body
 */
JwtStrategy.prototype.authenticate = function(req, options) {
    var self = this;

    var token = self._jwtFromRequest(req);

    if (!token) {
        return self.fail(new Error("No auth token"));
    }

    this._secretOrKeyProvider(req, token, function(secretOrKeyError, secretOrKey) {
        if (secretOrKeyError) {
            self.fail(secretOrKeyError)
        } else {
            // Verify the JWT
            JwtStrategy.JwtVerifier(token, secretOrKey, self._verifOpts, function(jwt_err, payload) {
                if (jwt_err) {
                    return self.fail(jwt_err);
                } else {
                    // Pass the parsed token to the user
                    var verified = function(err, user, info) {
                        if(err) {
                            return self.error(err);
                        } else if (!user) {
                            return self.fail(info);
                        } else {
                            return self.success(user, info);
                        }
                    };

                    try {
                        if (self._passReqToCallback) {
                            self._verify(req, payload, verified);
                        } else {
                            self._verify(payload, verified);
                        }
                    } catch(ex) {
                        self.error(ex);
                    }
                }
            });
        }
    });
};



/**
 * Export the Jwt Strategy
 */
 module.exports = JwtStrategy;


/***/ }),

/***/ "./node_modules/passport-jwt/lib/verify_jwt.js":
/*!*****************************************************!*\
  !*** ./node_modules/passport-jwt/lib/verify_jwt.js ***!
  \*****************************************************/
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

var jwt = __webpack_require__(/*! jsonwebtoken */ "jsonwebtoken");

module.exports  = function(token, secretOrKey, options, callback) {
    return jwt.verify(token, secretOrKey, options, callback);
};


/***/ }),

/***/ "./node_modules/passport-strategy/lib/index.js":
/*!*****************************************************!*\
  !*** ./node_modules/passport-strategy/lib/index.js ***!
  \*****************************************************/
/***/ ((module, exports, __webpack_require__) => {

/**
 * Module dependencies.
 */
var Strategy = __webpack_require__(/*! ./strategy */ "./node_modules/passport-strategy/lib/strategy.js");


/**
 * Expose `Strategy` directly from package.
 */
exports = module.exports = Strategy;

/**
 * Export constructors.
 */
exports.Strategy = Strategy;


/***/ }),

/***/ "./node_modules/passport-strategy/lib/strategy.js":
/*!********************************************************!*\
  !*** ./node_modules/passport-strategy/lib/strategy.js ***!
  \********************************************************/
/***/ ((module) => {

/**
 * Creates an instance of `Strategy`.
 *
 * @constructor
 * @api public
 */
function Strategy() {
}

/**
 * Authenticate request.
 *
 * This function must be overridden by subclasses.  In abstract form, it always
 * throws an exception.
 *
 * @param {Object} req The request to authenticate.
 * @param {Object} [options] Strategy-specific options.
 * @api public
 */
Strategy.prototype.authenticate = function(req, options) {
  throw new Error('Strategy#authenticate must be overridden by subclass');
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;


/***/ }),

/***/ "./apps/stalk-marks-app/src/app.controller.ts":
/*!****************************************************!*\
  !*** ./apps/stalk-marks-app/src/app.controller.ts ***!
  \****************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";

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

"use strict";

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
let AppModule = class AppModule {
};
AppModule = __decorate([
    (0, common_1.Module)({
        imports: [
            config_1.ConfigModule.forRoot({ isGlobal: true, envFilePath: '.env' }),
            prisma_module_1.PrismaModule,
            auth_module_1.AuthModule,
            user_module_1.UserModule,
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

"use strict";

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

"use strict";

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
let AuthController = class AuthController {
    constructor(authService) {
        this.authService = authService;
    }
    signUp(data) {
        return this.authService.signUp(data);
    }
    signIn(data) {
        return this.authService.signIn(data);
    }
    async refreshToken(req, id, refreshToken) {
        const tokens = await this.authService.refreshToken(id, refreshToken);
        console.log('refreshToken', id, refreshToken, tokens);
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
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_b = typeof dto_1.SignUpData !== "undefined" && dto_1.SignUpData) === "function" ? _b : Object]),
    __metadata("design:returntype", void 0)
], AuthController.prototype, "signUp", null);
__decorate([
    (0, common_1.Post)('signIn'),
    (0, decorators_1.Public)(),
    (0, common_1.HttpCode)(common_1.HttpStatus.CREATED),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_c = typeof dto_1.SignInData !== "undefined" && dto_1.SignInData) === "function" ? _c : Object]),
    __metadata("design:returntype", void 0)
], AuthController.prototype, "signIn", null);
__decorate([
    (0, common_1.Post)('refresh'),
    (0, decorators_1.Public)(),
    (0, common_1.UseGuards)(guards_1.RtGuard),
    (0, common_1.HttpCode)(common_1.HttpStatus.OK),
    __param(0, (0, common_2.Req)()),
    __param(1, (0, decorators_1.GetCurrentUserId)()),
    __param(2, Cookies('refresh_token')),
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

"use strict";

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

"use strict";

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

"use strict";

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
            return tokens;
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
        return tokens;
    }
    async logOut(id) {
        return true;
    }
    async refresh() { }
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

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));


/***/ }),

/***/ "./apps/stalk-marks-app/src/auth/strategies/at.strategy.ts":
/*!*****************************************************************!*\
  !*** ./apps/stalk-marks-app/src/auth/strategies/at.strategy.ts ***!
  \*****************************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";

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
const passport_jwt_1 = __webpack_require__(/*! passport-jwt */ "./node_modules/passport-jwt/lib/index.js");
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

"use strict";

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
const passport_jwt_1 = __webpack_require__(/*! passport-jwt */ "./node_modules/passport-jwt/lib/index.js");
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

/***/ "./apps/stalk-marks-app/src/common/decorators/get-current-user-id.decorator.ts":
/*!*************************************************************************************!*\
  !*** ./apps/stalk-marks-app/src/common/decorators/get-current-user-id.decorator.ts ***!
  \*************************************************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

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

"use strict";

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

"use strict";

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


/***/ }),

/***/ "./apps/stalk-marks-app/src/common/decorators/public.decorator.ts":
/*!************************************************************************!*\
  !*** ./apps/stalk-marks-app/src/common/decorators/public.decorator.ts ***!
  \************************************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

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

"use strict";

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

"use strict";

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

"use strict";

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

/***/ "./apps/stalk-marks-app/src/prisma/prisma.module.ts":
/*!**********************************************************!*\
  !*** ./apps/stalk-marks-app/src/prisma/prisma.module.ts ***!
  \**********************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";

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

"use strict";

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

"use strict";

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

"use strict";

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

"use strict";

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

"use strict";
module.exports = require("@nestjs/common");

/***/ }),

/***/ "@nestjs/config":
/*!*********************************!*\
  !*** external "@nestjs/config" ***!
  \*********************************/
/***/ ((module) => {

"use strict";
module.exports = require("@nestjs/config");

/***/ }),

/***/ "@nestjs/core":
/*!*******************************!*\
  !*** external "@nestjs/core" ***!
  \*******************************/
/***/ ((module) => {

"use strict";
module.exports = require("@nestjs/core");

/***/ }),

/***/ "@nestjs/graphql":
/*!**********************************!*\
  !*** external "@nestjs/graphql" ***!
  \**********************************/
/***/ ((module) => {

"use strict";
module.exports = require("@nestjs/graphql");

/***/ }),

/***/ "@nestjs/jwt":
/*!******************************!*\
  !*** external "@nestjs/jwt" ***!
  \******************************/
/***/ ((module) => {

"use strict";
module.exports = require("@nestjs/jwt");

/***/ }),

/***/ "@nestjs/passport":
/*!***********************************!*\
  !*** external "@nestjs/passport" ***!
  \***********************************/
/***/ ((module) => {

"use strict";
module.exports = require("@nestjs/passport");

/***/ }),

/***/ "@prisma/client":
/*!*********************************!*\
  !*** external "@prisma/client" ***!
  \*********************************/
/***/ ((module) => {

"use strict";
module.exports = require("@prisma/client");

/***/ }),

/***/ "@prisma/client/runtime/library":
/*!*************************************************!*\
  !*** external "@prisma/client/runtime/library" ***!
  \*************************************************/
/***/ ((module) => {

"use strict";
module.exports = require("@prisma/client/runtime/library");

/***/ }),

/***/ "argon2":
/*!*************************!*\
  !*** external "argon2" ***!
  \*************************/
/***/ ((module) => {

"use strict";
module.exports = require("argon2");

/***/ }),

/***/ "jsonwebtoken":
/*!*******************************!*\
  !*** external "jsonwebtoken" ***!
  \*******************************/
/***/ ((module) => {

"use strict";
module.exports = require("jsonwebtoken");

/***/ }),

/***/ "url":
/*!**********************!*\
  !*** external "url" ***!
  \**********************/
/***/ ((module) => {

"use strict";
module.exports = require("url");

/***/ }),

/***/ "util":
/*!***********************!*\
  !*** external "util" ***!
  \***********************/
/***/ ((module) => {

"use strict";
module.exports = require("util");

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
// This entry need to be wrapped in an IIFE because it need to be in strict mode.
(() => {
"use strict";
var exports = __webpack_exports__;
/*!******************************************!*\
  !*** ./apps/stalk-marks-app/src/main.ts ***!
  \******************************************/

Object.defineProperty(exports, "__esModule", ({ value: true }));
const core_1 = __webpack_require__(/*! @nestjs/core */ "@nestjs/core");
const app_module_1 = __webpack_require__(/*! ./app.module */ "./apps/stalk-marks-app/src/app.module.ts");
async function bootstrap() {
    const app = await core_1.NestFactory.create(app_module_1.AppModule);
    await app.listen(3030);
}
bootstrap();

})();

/******/ })()
;