import { ConfigService } from '@nestjs/config';
export declare class AppService {
    private readonly config;
    constructor(config: ConfigService);
    getHello(): string;
}
