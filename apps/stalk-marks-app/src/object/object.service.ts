import { Injectable } from '@nestjs/common';
import { Neo4jService } from '../neo4j/neo4j.service';

@Injectable()
export class ObjectService {
  constructor() {}

  async test() {
  
    return 'test';
  }
}
