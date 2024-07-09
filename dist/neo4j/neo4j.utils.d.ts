import { ConfigService } from '@nestjs/config';
import { Neo4jConfig } from './config/types';
export declare class ConnectionError extends Error {
    private details;
    constructor(error: Error);
}
export declare const createDatabaseConfig: (config: ConfigService, neo4jConfig: Neo4jConfig) => Neo4jConfig;
