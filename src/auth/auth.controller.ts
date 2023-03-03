import { Body, Controller, Get, Post, Req, Res } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { AuthDto } from './dtos/auth.dto';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  async signup(@Body() dto: AuthDto) {
    return this.authService.signup(dto);
  }

  @Post('login')
  async login(@Body() dto: AuthDto, @Req() req, @Res() res) {
    return this.authService.login(dto, req, res);
  }

  @Get('logout')
  async logout(@Req() req, @Res() res) {
    return this.authService.logout(req, res);
  }
}
