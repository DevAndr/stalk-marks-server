import { Tokens } from "../types";

export const setTokensCookie = (req: Request, tokens: Tokens) => {
 // @ts-ignore
 req.res.cookie("accessToken", `${tokens.accessToken}`, {
    httpOnly: true,
    maxAge: 50000 //1000 * 60 * 60 * 24 * 7,
  });

  // @ts-ignore
  req.res.cookie("refreshToken", `${tokens.refreshToken}`, {
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24 * 30,
  });
}