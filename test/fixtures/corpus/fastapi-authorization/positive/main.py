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
