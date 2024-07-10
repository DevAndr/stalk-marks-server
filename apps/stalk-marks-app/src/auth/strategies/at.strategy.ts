import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { JwtPayload } from '../types';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(config: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        // AtStrategy.extractJWT,
        ExtractJwt.fromAuthHeaderAsBearerToken(),
      ]),
      secretOrKey: config.get<string>('AT_SECRET'),
    });
  }

  async validate(payload: JwtPayload) {
    // console.log("AtStrategy", payload);
    return payload;
  }

  private static extractJWT(req: any): string | null {
    const cookies = req.cookies;
    console.log('AtStrategy');

    if (cookies) {
      if (!cookies?.accessToken && cookies?.refreshToken) {
        // console.log("request tokens", cookies?.refresh_token);
      }

      return cookies?.accessToken;
    }

    return null;
  }
}
