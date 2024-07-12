export type JwtPayload = {
  userName: string;
  sub: string;
};

export type JwtPayloadWithRt = JwtPayload & { refreshToken: string };

export type Tokens = {
  accessToken: string;
  refreshToken: string;
};

type User = {
  userName: string;
  email: string;
};

export type SignInResponse = {
  user: User;
  tokens: Tokens;
};

export type SignUpResponse = {} & SignInResponse;
