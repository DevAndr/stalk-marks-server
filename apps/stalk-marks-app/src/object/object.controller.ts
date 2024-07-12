import { Controller, Get, Post } from '@nestjs/common';
import { CreateObjectDto } from './dto/index';
import { ObjectService } from './object.service';
import { Public } from '../common/decorators';

@Controller('object')
export class ObjectController {
    constructor(private readonly objectService: ObjectService) {}


    @Post('create')
    async create(data: CreateObjectDto) {
        
    }


    @Get('test')
    @Public()
    test() {
        return this.objectService.test();
    }
}
