import { BadRequestException, Injectable } from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import { AuthDto } from './dtos/auth.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { jwtSecret } from '../utils/constants';
import { Request, Response } from 'express';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwtService: JwtService) {}

  async signup(dto: AuthDto) {
    const { email, password } = dto;
    const foundUser = await this.prisma.user.findUnique({ where: { email } });
    if (foundUser) {
      throw new BadRequestException('User already exists');
    }
    const hashedPwd = await this.hashPassword(password);
    const user = await this.prisma.user.create({
      data: {
        email,
        hashedPwd,
      },
    });

    return user;
  }

  async login(dto: AuthDto, req: Request, res: Response) {
    const { email, password } = dto;
    const foundUser = await this.prisma.user.findUnique({ where: { email } });
    if (!foundUser) {
      throw new BadRequestException('Wrong credentials');
    }
    const isMatch = await bcrypt.compare(password, foundUser.hashedPwd);
    if (!isMatch) {
      throw new BadRequestException('Wrong credentials');
    }
    const token = await this.jwtService.signAsync(
      { email: foundUser.email, sub: foundUser.id },
      { secret: jwtSecret },
    );
    if (!token) {
      throw new BadRequestException('Wrong credentials');
    }

    res.cookie('token', token);

    return res.send({ message: 'Logged succesfully' });
  }

  async logout(req: Request, res: Response) {
    res.clearCookie('token');
    return res.send({ message: 'Logged out succesfully' });
  }

  async hashPassword(password: string) {
    const saltOrRounds = 10;
    return await bcrypt.hash(password, saltOrRounds);
  }
}
