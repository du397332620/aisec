import { applyDecorators, CanActivate, ExecutionContext, Injectable, UnauthorizedException, UseGuards } from "@nestjs/common";

@Injectable()
export class LoggedInGuard implements CanActivate {
  canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();
    if (!request.user) throw new UnauthorizedException();
    return true;
  }
}

export function LoggedIn() {
  return applyDecorators(UseGuards(LoggedInGuard));
}
