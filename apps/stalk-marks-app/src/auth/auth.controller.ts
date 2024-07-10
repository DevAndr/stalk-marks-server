import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { GetCurrentUserId, Public } from '../common/decorators';
import { AuthService } from './auth.service';
import { SignInData, SignUpData } from './dto';
import { RtGuard } from '../common/guards';
import { Tokens } from './types';
import { Req } from '@nestjs/common';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signUp')
  @Public()
  @HttpCode(HttpStatus.CREATED)
  signUp(@Body() data: SignUpData) {
    return this.authService.signUp(data);
  }

  @Post('signIn')
  @Public()
  @HttpCode(HttpStatus.CREATED)
  signIn(@Body() data: SignInData) {
    return this.authService.signIn(data);
  }

  @Post('refresh')
  @Public()
  @UseGuards(RtGuard)
  @HttpCode(HttpStatus.OK)
  async refreshToken(
    @Req() req,
    @GetCurrentUserId() id: string,
    @Cookies('refresh_token') refreshToken: string,
  ) {
    const tokens = await this.authService.refreshToken(id, refreshToken);
    console.log('refreshToken', id, refreshToken, tokens);
    // this.setTokensCookie(req, tokens);
    return tokens;
  }

  @Post('logOut')
  @HttpCode(HttpStatus.OK)
  async logOutLocal(@GetCurrentUserId() id: string): Promise<boolean> {
    return this.authService.logOut(id);
  }
}
