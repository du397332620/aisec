from fastapi import Depends, FastAPI


def get_current_user():
    return {"id": 7}


app = FastAPI(dependencies=[Depends(get_current_user)])


@app.post("/document/delete")
def delete_document(request: DeleteDocumentRequest, db=Depends(get_db)):
    report = db.get(Report, request.report_id)
    db.delete(report)
    db.commit()
    return {"deleted": True}


@app.post("/permissions/grant")
def grant_permission(request: PermissionGrantRequest, service=Depends(get_permission_service)):
    return service.grant(request.subject, request.permission)
