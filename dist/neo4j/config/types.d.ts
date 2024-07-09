import { Connection } from 'cypher-query-builder';
import { Driver } from 'neo4j-driver';
export type Neo4jScheme = 'neo4j' | 'neo4j+s' | 'neo4j+ssc' | 'neo4j+s+s' | 'bolt' | 'bolt+s' | 'bolt+ssc' | 'bolt+s+s';
export interface Neo4jConfig {
    scheme: Neo4jScheme;
    host: string;
    port: number;
    username: string;
    password: string;
    database?: string;
}
export type ConnectionWithDriver = Connection & {
    driver: Driver;
};
