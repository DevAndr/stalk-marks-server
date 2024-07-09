import { ConfigService } from '@nestjs/config';
import { Neo4jConfig } from './config/types';

export class ConnectionError extends Error {
  private details: string;

  constructor(error: Error) {
    super();

    this.message = 'Could not connect to Neo4j';
    this.name = 'ConnectionError';
    this.details = error.message;
    this.stack = error.stack;
  }
}

export const createDatabaseConfig = (
  config: ConfigService,
  neo4jConfig: Neo4jConfig,
): Neo4jConfig =>
  neo4jConfig || {
    host: config.get('NEO4J_HOST'),
    port: config.get('NEO4J_PORT'),
    username: config.get('NEO4J_USERNAME'),
    password: config.get('NEO4J_PASSWORD'),
    scheme: config.get('NEO4J_DATABASE_SCHEME'),
  };
