/******/ (() => { // webpackBootstrap
/******/ 	"use strict";
/******/ 	var __webpack_modules__ = ({

/***/ "./apps/storage/src/storage.controller.ts":
/*!************************************************!*\
  !*** ./apps/storage/src/storage.controller.ts ***!
  \************************************************/
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
exports.StorageController = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const config_1 = __webpack_require__(/*! @nestjs/config */ "@nestjs/config");
const platform_express_1 = __webpack_require__(/*! @nestjs/platform-express */ "@nestjs/platform-express");
const multer_1 = __webpack_require__(/*! multer */ "multer");
const storage_service_1 = __webpack_require__(/*! ./storage.service */ "./apps/storage/src/storage.service.ts");
const utils_1 = __webpack_require__(/*! ./utils */ "./apps/storage/src/utils/index.ts");
let StorageController = class StorageController {
    constructor(storageService, configService) {
        this.storageService = storageService;
        this.configService = configService;
    }
    uploadFile(file) {
        console.log(file);
        const url = `${this.configService.get('HOST_URL_STORAGE_SERVICE')}/storage/images/${file.filename}`;
        const response = {
            originalname: file.originalname,
            filename: file.filename,
            url,
        };
        return response;
    }
    seeUploadedFile(image, res) {
        const path = `${this.configService.get('PATH_STORAGE_IMAGES')}/uploads`;
        return res.sendFile(image, { root: path });
    }
};
__decorate([
    (0, common_1.Post)('upload'),
    (0, common_1.UseInterceptors)((0, platform_express_1.FileInterceptor)('file', {
        storage: (0, multer_1.diskStorage)({
            destination: utils_1.pathUploadImages,
            filename: utils_1.editFileName,
        }),
        fileFilter: utils_1.imageFileFilter,
    })),
    __param(0, (0, common_1.UploadedFile)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_d = typeof Express !== "undefined" && (_c = Express.Multer) !== void 0 && _c.File) === "function" ? _d : Object]),
    __metadata("design:returntype", void 0)
], StorageController.prototype, "uploadFile", null);
__decorate([
    (0, common_1.Get)('images/:img'),
    __param(0, (0, common_1.Param)('img')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object]),
    __metadata("design:returntype", void 0)
], StorageController.prototype, "seeUploadedFile", null);
StorageController = __decorate([
    (0, common_1.Controller)(),
    __metadata("design:paramtypes", [typeof (_a = typeof storage_service_1.StorageService !== "undefined" && storage_service_1.StorageService) === "function" ? _a : Object, typeof (_b = typeof config_1.ConfigService !== "undefined" && config_1.ConfigService) === "function" ? _b : Object])
], StorageController);
exports.StorageController = StorageController;


/***/ }),

/***/ "./apps/storage/src/storage.module.ts":
/*!********************************************!*\
  !*** ./apps/storage/src/storage.module.ts ***!
  \********************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.StorageModule = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const config_1 = __webpack_require__(/*! @nestjs/config */ "@nestjs/config");
const platform_express_1 = __webpack_require__(/*! @nestjs/platform-express */ "@nestjs/platform-express");
const storage_controller_1 = __webpack_require__(/*! ./storage.controller */ "./apps/storage/src/storage.controller.ts");
const storage_service_1 = __webpack_require__(/*! ./storage.service */ "./apps/storage/src/storage.service.ts");
let StorageModule = class StorageModule {
};
StorageModule = __decorate([
    (0, common_1.Module)({
        imports: [
            config_1.ConfigModule.forRoot({
                envFilePath: './apps/storage/.env',
                isGlobal: true,
            }),
            platform_express_1.MulterModule.registerAsync({
                imports: [config_1.ConfigModule],
                inject: [config_1.ConfigService],
                useFactory: async (configService) => ({
                    dest: `${configService.get('PATH_STORAGE_IMAGES')}/uploads`,
                    limits: {
                        fileSize: 5 * 1024 * 1024,
                    },
                }),
            }),
        ],
        controllers: [storage_controller_1.StorageController],
        providers: [storage_service_1.StorageService],
    })
], StorageModule);
exports.StorageModule = StorageModule;


/***/ }),

/***/ "./apps/storage/src/storage.service.ts":
/*!*********************************************!*\
  !*** ./apps/storage/src/storage.service.ts ***!
  \*********************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.StorageService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
let StorageService = class StorageService {
    getHello() {
        return 'Hello World!';
    }
};
StorageService = __decorate([
    (0, common_1.Injectable)()
], StorageService);
exports.StorageService = StorageService;


/***/ }),

/***/ "./apps/storage/src/utils/index.ts":
/*!*****************************************!*\
  !*** ./apps/storage/src/utils/index.ts ***!
  \*****************************************/
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.imageFileFilter = exports.pathUploadImages = exports.editFileName = void 0;
const editFileName = (req, file, callback) => {
    const [name, ext] = file.originalname.split('.');
    console.log('editFileName', name, ext, process.env.PATH_STORAGE_IMAGES);
    const randomName = Array(4)
        .fill(null)
        .map(() => Math.round(Math.random() * 16).toString(16))
        .join('');
    callback(null, `${name}-${randomName}.${ext}`);
};
exports.editFileName = editFileName;
const pathUploadImages = (req, file, callback) => {
    callback(null, `${process.env.PATH_STORAGE_IMAGES}/uploads`);
};
exports.pathUploadImages = pathUploadImages;
const imageFileFilter = (req, file, callback) => {
    if (!file.originalname.match(/\.(jpg|jpeg|png|gif)$/)) {
        return callback(new Error('Only image files are allowed!'), false);
    }
    callback(null, true);
};
exports.imageFileFilter = imageFileFilter;


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

/***/ "@nestjs/platform-express":
/*!*******************************************!*\
  !*** external "@nestjs/platform-express" ***!
  \*******************************************/
/***/ ((module) => {

module.exports = require("@nestjs/platform-express");

/***/ }),

/***/ "multer":
/*!*************************!*\
  !*** external "multer" ***!
  \*************************/
/***/ ((module) => {

module.exports = require("multer");

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
/*!**********************************!*\
  !*** ./apps/storage/src/main.ts ***!
  \**********************************/

Object.defineProperty(exports, "__esModule", ({ value: true }));
const core_1 = __webpack_require__(/*! @nestjs/core */ "@nestjs/core");
const storage_module_1 = __webpack_require__(/*! ./storage.module */ "./apps/storage/src/storage.module.ts");
async function bootstrap() {
    const app = await core_1.NestFactory.create(storage_module_1.StorageModule);
    await app.listen(3031);
}
bootstrap();

})();

/******/ })()
;