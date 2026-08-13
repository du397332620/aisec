import { Body, Controller, Post } from "@nestjs/common";
import { LoggedIn } from "./security/nest-security.js";

@Controller("reports")
export class ReportsController {
  @Post("admin/export")
  exportReports() {
    return { queued: true };
  }

  @LoggedIn()
  @Post("detail")
  async reportDetail(@Body() request: ReportDetailRequest) {
    const report = await this.reports.findOne({ where: { id: request.report_id } });
    return { data: { id: report.id, tenantId: report.tenantId } };
  }
}
