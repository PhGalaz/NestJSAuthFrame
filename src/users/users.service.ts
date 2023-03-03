import { Injectable } from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import { Request } from 'express';

@Injectable()
export class UsersService {
  constructor(private prisma: PrismaService) {}

  async getMyUser(req: Request) {
    const decodedUser = req.user as { id: string; email: string };
    const user = await this.prisma.user.findUnique({
      where: {
        id: decodedUser.id,
        email: decodedUser.email,
      },
    });

    delete user.hashedPwd;

    return { user };
  }

  async getAllUsers() {
    return await this.prisma.user.findMany({
      select: { id: true, email: true },
    });
  }
}
