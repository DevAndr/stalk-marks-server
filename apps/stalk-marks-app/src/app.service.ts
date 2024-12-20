import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AppService {
  constructor(private readonly config: ConfigService) {}

  getHello(): string {
    const host = this.config.get('NEO4J_HOST');
    console.log(host);

    return 'Hello World!';
  }
}
