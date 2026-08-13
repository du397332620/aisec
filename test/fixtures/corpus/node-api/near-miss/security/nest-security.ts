import { applyDecorators, CanActivate, ExecutionContext, ForbiddenException, Injectable, UnauthorizedException, UseGuards } from "@nestjs/common";

@Injectable()
export class LoggedInGuard implements CanActivate {
  canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();
    if (!request.user) throw new UnauthorizedException();
    return true;
  }
}

@Injectable()
export class TenantScopeGuard implements CanActivate {
  canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();
    if (request.user.tenantId !== request.body.tenantId) throw new ForbiddenException();
    return true;
  }
}

@Injectable()
export class AdminGuard implements CanActivate {
  canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();
    if (request.user.role !== "admin") throw new ForbiddenException();
    return true;
  }
}

export function LoggedIn() {
  return applyDecorators(UseGuards(LoggedInGuard));
}

export function TenantAccess() {
  return applyDecorators(LoggedIn(), UseGuards(TenantScopeGuard));
}

export function AdminOnly() {
  return applyDecorators(LoggedIn(), UseGuards(AdminGuard));
}
