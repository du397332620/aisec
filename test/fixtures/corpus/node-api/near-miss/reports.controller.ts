import { Body, Controller, Post, Req, UseGuards } from "@nestjs/common";

@Controller("reports")
@UseGuards(JwtAuthGuard)
export class ReportsController {
  @Post("admin/export")
  exportReports() {
    return { queued: true };
  }

  @Post("detail")
  async reportDetail(@Body() request: ReportDetailRequest, @Req() req: any) {
    const report = await this.reports.findOne({
      where: { id: request.report_id, tenantId: req.user.tenantId },
    });
    return { data: { id: report.id, tenantId: report.tenantId } };
  }
}
