"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var Neo4jModule_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.Neo4jModule = void 0;
const common_1 = require("@nestjs/common");
const config_1 = require("@nestjs/config");
const cypher_query_builder_1 = require("cypher-query-builder");
const neo4j_driver_1 = require("neo4j-driver");
const neo4j_constans_1 = require("./neo4j.constans");
const neo4j_utils_1 = require("./neo4j.utils");
let Neo4jModule = Neo4jModule_1 = class Neo4jModule {
    static forRootAsync(neo4jConfig) {
        return {
            module: Neo4jModule_1,
            imports: [config_1.ConfigModule],
            global: true,
            providers: [
                {
                    provide: neo4j_constans_1.NEO4J_CONFIG,
                    inject: [config_1.ConfigService],
                    useFactory: (config) => {
                        return (0, neo4j_utils_1.createDatabaseConfig)(config, neo4jConfig);
                    },
                },
                {
                    provide: neo4j_constans_1.NEO4J_CONNECTION,
                    inject: [neo4j_constans_1.NEO4J_CONFIG],
                    useFactory: async (config) => {
                        const { host, scheme, port, username, password } = config;
                        try {
                            const connection = new cypher_query_builder_1.Connection(`${scheme}://${host}:${port}`, {
                                username,
                                password,
                            });
                            const driver = neo4j_driver_1.default.driver(`${scheme}://${host}:${port}`, neo4j_driver_1.default.auth.basic(username, password));
                            await driver.verifyAuthentication();
                            return connection;
                        }
                        catch (error) {
                            throw new neo4j_utils_1.ConnectionError(error);
                        }
                    },
                },
            ],
        };
    }
};
Neo4jModule = Neo4jModule_1 = __decorate([
    (0, common_1.Module)({})
], Neo4jModule);
exports.Neo4jModule = Neo4jModule;
//# sourceMappingURL=neo4j.module.js.map