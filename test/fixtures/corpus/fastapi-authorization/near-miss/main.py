from fastapi import Depends, FastAPI, HTTPException


def get_current_user():
    return {"id": 7}


def require_report_access(db, current_user, report_id):
    report = db.get(Report, report_id)
    if report.user_id != current_user.id:
        raise HTTPException(status_code=403)
    return report


app = FastAPI(dependencies=[Depends(get_current_user)])


@app.post("/document/delete")
def delete_document(
    request: DeleteDocumentRequest,
    current_user=Depends(get_current_user),
    db=Depends(get_db),
):
    report = require_report_access(db, current_user, request.report_id)
    db.delete(report)
    db.commit()
    return {"deleted": True}
