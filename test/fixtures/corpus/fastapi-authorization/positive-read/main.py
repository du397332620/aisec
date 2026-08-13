from fastapi import Depends, FastAPI

app = FastAPI(dependencies=[Depends(get_current_user)])


@app.post("/document/detail")
def detail(request: ReportRequest, db=Depends(get_db)):
    return db.get(Report, request.report_id)
