import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateUserDto } from './dto';

@Injectable()
export class UserService {
  constructor(private readonly prisma: PrismaService) {}

  async create(data: CreateUserDto) {
    return this.prisma.user.create({ data });
  }

  async isUniqueUsername(userName: string) {
    const user = await this.prisma.user.findFirst({
      where: {
        userName,
      },
    });

    return !user;
  }

  async isUniqueEmail(email: string) {
    const user = await this.prisma.user.findFirst({
      where: {
        email,
      },
    });

    return !user;
  }
}
