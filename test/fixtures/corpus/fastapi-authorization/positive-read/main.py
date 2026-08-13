from fastapi import Depends, FastAPI

app = FastAPI(dependencies=[Depends(get_current_user)])


@app.post(
    "/document/detail",
    responses={200: {"content": {"application/json": {"example": {"data": {"id": 1, "user_id": 7}}}}}},
)
def detail(request: ReportRequest, db=Depends(get_db)):
    return db.get(Report, request.report_id)
