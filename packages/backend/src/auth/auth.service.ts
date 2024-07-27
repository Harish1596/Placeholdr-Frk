import { HttpStatus, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthUser } from 'src/types/AuthUser';
import { UserService } from 'src/user/user.service';
import * as O from 'fp-ts/Option';
import * as E from 'fp-ts/Either';
import {
  AccessTokenPayload,
  AuthTokens,
  RefreshTokenPayload,
} from 'src/types/AuthTokens';
import * as argon2 from 'argon2';
import { RESTError } from 'src/types/RESTError';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UserService,
    private prismaService: PrismaService,
    private jwtService: JwtService,
  ) {}

  async generateAuthTokens(userUid: string) {
    const accessTokenPayload: AccessTokenPayload = {
      iss: process.env.VITE_BASE_URL,
      sub: userUid,
      aud: [process.env.VITE_BASE_URL],
    };

    const refreshToken = await this.generateRefreshToken(userUid);
    if (E.isLeft(refreshToken)) return E.left(refreshToken.left);

    return E.right(<AuthTokens>{
      access_token: await this.jwtService.sign(accessTokenPayload, {
        expiresIn: process.env.ACCESS_TOKEN_VALIDITY, //1 Day
      }),
      refresh_token: refreshToken.right,
    });
  }

  private async generateRefreshToken(userUid: string) {
    const refreshTokenPayload: RefreshTokenPayload = {
      iss: process.env.VITE_BASE_URL,
      sub: userUid,
      aud: [process.env.VITE_BASE_URL],
    };

    const refreshToken = await this.jwtService.sign(refreshTokenPayload, {
      expiresIn: process.env.REFRESH_TOKEN_VALIDITY, //7 Days
    });

    const refreshTokenHash = await argon2.hash(refreshToken);

    const updatedUser = await this.usersService.updateUserRefreshToken(
      refreshTokenHash,
      userUid,
    );
    if (E.isLeft(updatedUser))
      return E.left(<RESTError>{
        message: updatedUser.left,
        statusCode: HttpStatus.NOT_FOUND,
      });

    return E.right(refreshToken);
  }

  async checkIfProviderAccountExists(user: AuthUser, SSOUserData) {
    const provider = await this.prismaService.account.findUnique({
      where: {
        verifyProviderAccount: {
          provider: SSOUserData.provider,
          providerAccountId: SSOUserData.id,
        },
      },
    });

    if (!provider) return O.none;

    return O.some(provider);
  }
}
