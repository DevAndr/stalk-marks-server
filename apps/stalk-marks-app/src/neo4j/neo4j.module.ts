import { DynamicModule, Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { Connection } from 'cypher-query-builder';
import neo4j from 'neo4j-driver';
import { ConnectionWithDriver, Neo4jConfig } from './config/types';
import { NEO4J_CONFIG, NEO4J_CONNECTION } from './neo4j.constans';
import { ConnectionError, createDatabaseConfig } from './neo4j.utils';
import { Neo4jService } from './neo4j.service';

@Module({
  providers: [Neo4jService]
})
export class Neo4jModule {
  static forRootAsync(neo4jConfig?: Neo4jConfig): DynamicModule {
    return {
      module: Neo4jModule,
      imports: [ConfigModule],
      global: true,
      providers: [
        {
          provide: NEO4J_CONFIG,
          inject: [ConfigService],
          useFactory: (config: ConfigService) => {
            return createDatabaseConfig(config, neo4jConfig);
          },
        },
        {
          provide: NEO4J_CONNECTION,
          inject: [NEO4J_CONFIG],
          useFactory: async (config: Neo4jConfig) => {
            const { host, scheme, port, username, password } = config;

            console.log('Neo4jModule', { host, scheme, port, username, password });
            

            try {
              const connection = new Connection(`${scheme}://${host}:${port}`, {
                username,
                password,
              }) as ConnectionWithDriver;

              const driver = neo4j.driver(
                `${scheme}://${host}:${port}`,
                neo4j.auth.basic(username, password),
              );

              await driver.verifyAuthentication(); 

              return connection;
            } catch (error) {
              throw new ConnectionError(error);
            }
          },
        },
      ],
      exports: [Neo4jService],
    };
  }
}
