"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createDatabaseConfig = exports.ConnectionError = void 0;
class ConnectionError extends Error {
    constructor(error) {
        super();
        this.message = 'Could not connect to Neo4j';
        this.name = 'ConnectionError';
        this.details = error.message;
        this.stack = error.stack;
    }
}
exports.ConnectionError = ConnectionError;
const createDatabaseConfig = (config, neo4jConfig) => neo4jConfig || {
    host: config.get('NEO4J_HOST'),
    port: config.get('NEO4J_PORT'),
    username: config.get('NEO4J_USERNAME'),
    password: config.get('NEO4J_PASSWORD'),
    scheme: config.get('NEO4J_DATABASE_SCHEME'),
};
exports.createDatabaseConfig = createDatabaseConfig;
//# sourceMappingURL=neo4j.utils.js.map