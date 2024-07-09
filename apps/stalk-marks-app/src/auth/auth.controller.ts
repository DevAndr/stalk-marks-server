import { Body, Controller, HttpCode, HttpStatus, Post } from '@nestjs/common';
import { SignInData, SignUpData } from './dto';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signUp')
  @HttpCode(HttpStatus.CREATED)
  signUp(@Body() data: SignUpData) {
    return this.authService.signUp(data);
  }

  @Post('signIn')
  @HttpCode(HttpStatus.CREATED)
  signIn(@Body() data: SignInData) {
    return this.authService.signIn(data);
  }
}
