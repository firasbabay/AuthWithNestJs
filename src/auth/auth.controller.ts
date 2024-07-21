import { Body, Controller, Post } from '@nestjs/common';
import { SignUpDto } from './dtos/signup.dto';
import { AuthService } from './auth.service';
import { LoginDto } from './dtos/login.dto';
import { RefreshTokenDto } from './dtos/refresh-token.dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}
  // POST signup
  @Post('signup')
  async signup(@Body() signupData: SignUpDto) {
    return this.authService.signup(signupData);
  }

  // POST Login
  @Post('login')
  async login(@Body() loginData: LoginDto) {
    return this.authService.login(loginData);
  }

  // POST refresh token
  @Post('refresh')
  async refreshToken(@Body() refreshTokenData: RefreshTokenDto) {
    return this.authService.refreshToken(refreshTokenData.refreshToken);
  }
}
