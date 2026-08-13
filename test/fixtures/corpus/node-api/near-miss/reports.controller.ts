import { Body, Controller, Post, Req } from "@nestjs/common";
import { AdminOnly, LoggedIn, TenantAccess } from "./security/nest-security.js";

@Controller("reports")
@LoggedIn()
export class ReportsController {
  @Post("admin/export")
  @AdminOnly()
  exportReports() {
    return { queued: true };
  }

  @TenantAccess()
  @Post("detail")
  async reportDetail(@Body() request: ReportDetailRequest, @Req() req: any) {
    const report = await this.reports.findOne({
      where: { id: request.report_id, tenantId: req.user.tenantId },
    });
    return { data: { id: report.id, tenantId: report.tenantId } };
  }
}
