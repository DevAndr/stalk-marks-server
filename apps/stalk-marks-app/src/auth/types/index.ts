export type JwtPayload = {
  userName: string;
  sub: string;
};

export type Tokens = {
  accessToken: string;
  refreshToken: string;
};