import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { Cookies, GetCurrentUser, GetCurrentUserId, Public } from '../common/decorators';
import { AuthService } from './auth.service';
import { SignInData, SignUpData } from './dto';
import { RtGuard } from '../common/guards';
import { Tokens } from './types';
import { Req } from '@nestjs/common';
import { setTokensCookie } from './utils';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signUp')
  @Public()
  @HttpCode(HttpStatus.CREATED)
  async signUp(@Req() req, @Body() data: SignUpData) {
    const signUpData = await this.authService.signUp(data);
    setTokensCookie(req, signUpData.tokens);
    return signUpData
  }

  @Post('signIn')
  @Public()
  @HttpCode(HttpStatus.CREATED)
  async signIn(@Req() req, @Body() data: SignInData) {
    const signInData = await this.authService.signIn(data);
    setTokensCookie(req, signInData.tokens);
    return this.authService.signIn(data);
  }

  @Post('refresh')
  @Public()
  @UseGuards(RtGuard)
  @HttpCode(HttpStatus.OK)
  async refreshToken(
    @Req() req,
    @GetCurrentUserId() id: string,
    @GetCurrentUser('refreshToken') refreshToken: string,
  ) {
    const tokens = await this.authService.refresh(id, refreshToken);
    console.log('refreshToken', id, refreshToken, tokens);
    setTokensCookie(req, tokens);
    return tokens;
  }

  @Post('logOut')
  @HttpCode(HttpStatus.OK)
  async logOutLocal(@GetCurrentUserId() id: string): Promise<boolean> {
    return this.authService.logOut(id);
  }


}
