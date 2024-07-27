import { Controller, Get, Request, Res, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { GoogleSSOGuard } from './guards/google-sso.guard';
import * as E from 'fp-ts/Either';
import { throwHTTPErr } from 'src/utils';
import { authCookieHandler } from './helper';
import { GithubSSOGuard } from './guards/github-sso.guard';

@Controller({ path: 'auth', version: '1' })
export class AuthController {
  constructor(private authService: AuthService) {}

  @Get('google')
  @UseGuards(GoogleSSOGuard)
  async googleAuth(@Request() req) {}

  @Get('google/callback')
  @UseGuards(GoogleSSOGuard)
  async googleAuthRedirect(@Request() req, @Res() res) {
    const authTokens = await this.authService.generateAuthTokens(req.user.uid);
    if (E.isLeft(authTokens)) throwHTTPErr(authTokens.left);
    authCookieHandler(res, authTokens.right, true);
  }

  @Get('github')
  @UseGuards(GithubSSOGuard)
  async githubAuth(@Request() req) {}

  @Get('github/callback')
  @UseGuards(GithubSSOGuard)
  async githubAuthRedirect(@Request() req, @Res() res) {
    const authTokens = await this.authService.generateAuthTokens(req.user.uid);
    if (E.isLeft(authTokens)) throwHTTPErr(authTokens.left);
    authCookieHandler(res, authTokens.right, true);
  }
}
