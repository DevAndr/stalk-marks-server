import { ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { GqlExecutionContext } from '@nestjs/graphql';
import { AuthGuard } from '@nestjs/passport';
import { Observable } from 'rxjs';

@Injectable()
export class AtGuard extends AuthGuard('jwt') {
  constructor(private reflector: Reflector) {
    super();
  }

  getRequest(ctx: ExecutionContext): any {
    if (ctx.getType() === 'http') {
      const request = ctx.switchToHttp().getRequest();
      // console.log("http", request.cookies);

      return request;
    } else {
      console.log('gql');

      const ctxGql = GqlExecutionContext.create(ctx);
      console.log(ctxGql.getContext().req.user);
      return ctxGql.getContext().req;
    }
  }

  canActivate(
    ctx: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const isPublic = this.reflector.getAllAndOverride('isPublic', [
      ctx.getHandler(),
      ctx.getClass(),
    ]);

    return isPublic ? true : super.canActivate(ctx);
  }
}
