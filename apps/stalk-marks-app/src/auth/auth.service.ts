import {
  ForbiddenException,
  HttpException,
  HttpStatus,
  Injectable,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import * as argon from 'argon2';
import { PrismaService } from '../prisma/prisma.service';
import { UserService } from '../user/user.service';
import { SignInData, SignUpData } from './dto';
import { JwtPayload, SignInResponse, SignUpResponse, Tokens } from './types';

@Injectable()
export class AuthService {
  constructor(
    private readonly config: ConfigService,
    private readonly prisma: PrismaService,
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
  ) {}

  async signUp(data: SignUpData): Promise<SignUpResponse> {
    const { userName, email, password, ...payload } = data;

    const checkUser = this.userService.isUniqueUsername(userName);

    if (checkUser) {
      const hashPassword = await argon.hash(data.password);

      const newUser = await this.userService
        .create({
          userName,
          email,
          hashPassword,
        })
        .catch((e) => {
          if (e instanceof PrismaClientKnownRequestError) {
            if (e.code === 'P2002') {
              throw new ForbiddenException(
                `пользователь с email или username уже существует`,
              );
            }
          }
          throw e;
        });

      const tokens = await this.createTokens(newUser.id, userName);
      await this.updateRefreshToken(newUser.id, tokens.refreshToken);

      return {user: {userName: newUser.userName, email: newUser.email}, tokens};
    } else {
      throw new HttpException(
        `Пользователь уже существует с такими данными: ${userName}`,
        HttpStatus.CONFLICT,
      );
    }
  }

  async signIn(data: SignInData): Promise<SignInResponse> {
    const user = await this.prisma.user.findFirst({
      where: {
        userName: data.userName,
      },
    });

    if (!user)
      throw new HttpException(
        'Неверный логин или пароль',
        HttpStatus.FORBIDDEN,
      );

    const isPasswordValid = await argon.verify(
      user.hashPassword,
      data.password,
    );

    if (!isPasswordValid)
      throw new HttpException('Неверный пароль', HttpStatus.FORBIDDEN);

    const tokens = await this.createTokens(user.id, user.userName);
    await this.updateRefreshToken(user.id, tokens.refreshToken);

    return {user: {userName: user.userName, email: user.email}, tokens};
  }

  async logOut(id: string) {
    return true;
  }

  async refresh(id: string, rt: string) {
    const user = await this.prisma.user.findUnique({
      where: {
        id,
      },
    });

    if (!user || !user.hashRefreshToken) throw new ForbiddenException('Access Denied');

    const rtMatches = await argon.verify(user.hashRefreshToken, rt);
    if (!rtMatches) throw new ForbiddenException('Access Denied');

    const tokens = await this.createTokens(user.id, user.email);
    await this.updateRefreshToken(user.id, tokens.refreshToken);

    return tokens;
  }

  async verify() {}

  async createTokens(id: string, userName: string): Promise<Tokens> {
    const jwtPayload: JwtPayload = {
      sub: id,
      userName,
    };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(jwtPayload, {
        expiresIn: '7d',
        secret: this.config.get<string>('AT_SECRET'),
      }),
      this.jwtService.signAsync(jwtPayload, {
        expiresIn: '30d',
        secret: this.config.get<string>('RT_SECRET'),
      }),
    ]);

    return { accessToken, refreshToken };
  }

  async updateRefreshToken(uid: string, refreshToken: string) {
    const hashRefreshToken = await argon.hash(refreshToken);
    await this.prisma.user.update({
      where: {
        id: uid,
      },
      data: {
        hashRefreshToken,
      },
    });
  }
}
