from fastapi import APIRouter, Depends, FastAPI, HTTPException


def get_current_user():
    return {"id": 7}


def require_report_access(db, current_user, report_id):
    report = db.get(Report, report_id)
    if report.user_id != current_user.id:
        raise HTTPException(status_code=403)
    return report


def enforce_control(current_user=Depends(get_current_user)):
    if "permissions:write" not in current_user.permissions:
        raise HTTPException(status_code=403)
    return current_user


app = FastAPI(dependencies=[Depends(get_current_user)])
permission_router = APIRouter(prefix="/permissions")


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


@permission_router.post("/grant")
def grant_permission(request: PermissionGrantRequest, service=Depends(get_permission_service)):
    return service.grant(request.subject, request.permission)


app.include_router(permission_router, dependencies=[Depends(enforce_control)])
