import { DynamicModule } from '@nestjs/common';
import { Neo4jConfig } from './config/types';
export declare class Neo4jModule {
    static forRootAsync(neo4jConfig?: Neo4jConfig): DynamicModule;
}
