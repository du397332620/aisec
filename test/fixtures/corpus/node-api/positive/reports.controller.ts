import { Body, Controller, Post, UseGuards } from "@nestjs/common";

@Controller("reports")
export class ReportsController {
  @Post("admin/export")
  exportReports() {
    return { queued: true };
  }

  @UseGuards(JwtAuthGuard)
  @Post("detail")
  async reportDetail(@Body() request: ReportDetailRequest) {
    const report = await this.reports.findOne({ where: { id: request.report_id } });
    return { data: { id: report.id, tenantId: report.tenantId } };
  }
}
