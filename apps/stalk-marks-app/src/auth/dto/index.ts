type AuthDto = {
  userName: string;
  password: string;
};

export type SignUpData = {
  email: string;
} & AuthDto;

export type SignInData = {} & AuthDto;
