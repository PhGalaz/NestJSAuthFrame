import { Controller, Get, UseGuards, Req } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { UsersService } from './users.service';
import { JwtAuthGuard } from '../auth/jwt.guard';
import { Request } from 'express';

@ApiTags('users')
@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @UseGuards(JwtAuthGuard)
  @Get('me')
  getMyUser(@Req() req: Request) {
    return this.usersService.getMyUser(req);
  }

  @Get()
  getAllUsers() {
    return this.usersService.getAllUsers();
  }
}
