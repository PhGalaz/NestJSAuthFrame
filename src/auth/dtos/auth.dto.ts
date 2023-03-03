import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString, Length } from 'class-validator';

export class AuthDto {
  @ApiProperty({ type: String, description: 'Email', required: true })
  @IsEmail()
  @IsNotEmpty()
  public email: string;

  @ApiProperty({ type: String, description: 'Password', required: true })
  @IsString()
  @IsNotEmpty()
  @Length(8, 20, { message: 'Password must be between 8 and 20 characters' })
  public password: string;
}
