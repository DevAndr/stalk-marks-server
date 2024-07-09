import {
  Controller,
  Get,
  Param,
  Post,
  Res,
  UploadedFile,
  UseInterceptors,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { FileInterceptor } from '@nestjs/platform-express';
import { diskStorage } from 'multer';
import { StorageService } from './storage.service';
import { editFileName, imageFileFilter, pathUploadImages } from './utils';

@Controller()
export class StorageController {
  constructor(
    private readonly storageService: StorageService,
    private readonly configService: ConfigService,
  ) {}

  @Post('upload')
  @UseInterceptors(
    FileInterceptor('file', {
      storage: diskStorage({
        destination: pathUploadImages,
        filename: editFileName,
      }),
      fileFilter: imageFileFilter,
    }),
  )
  uploadFile(@UploadedFile() file: Express.Multer.File) {
    console.log(file);

    const url = `${this.configService.get<string>(
      'HOST_URL_STORAGE_SERVICE',
    )}/storage/images/${file.filename}`;

    const response = {
      originalname: file.originalname,
      filename: file.filename,
      url,
    };
    return response;
  }

  @Get('images/:img')
  seeUploadedFile(@Param('img') image, @Res() res) {
    const path = `${this.configService.get<string>(
      'PATH_STORAGE_IMAGES',
    )}/uploads`;
    return res.sendFile(image, { root: path });
  }
}
