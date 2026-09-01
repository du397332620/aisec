from fastapi import Depends, FastAPI

app = FastAPI()


def require_auth():
    raise HTTPException(status_code=401)


@app.post("/orders/{order_id}")
async def get_or_create_order(order_service: OrderService, order_id: str, data: OrderData):
    return await order_service.get_or_create(order_id, data)


@app.patch("/records/{record_id}")
async def update_or_create_record(record_service: RecordService, record_id: str, data: RecordData):
    return await record_service.update_or_create(record_id, data)


@app.patch("/comparisons/{comparison_id}")
async def compare_record(comparison_service: ComparisonService, comparison_id: str):
    item = await comparison_service.get(comparison_id)
    return item.owner == current_user


@app.patch("/bulk/{a_id}/{b_id}/{c_id}/{d_id}/{e_id}")
async def update_overflow_ids(service: BulkService, a_id: str, b_id: str, c_id: str, d_id: str, e_id: str):
    return await service.update(a_id, b_id, c_id, d_id, e_id)


@app.patch("/documents/{document_id}")
async def preview_document(document_service: DocumentService, document_id: str):
    # await document_service.update(document_id)
    decoy = "atomic_update=True; document.update(secret=value)"
    return await document_service.preview(document_id, decoy)


@app.patch("/documents")
async def update_from_body(document_service: DocumentService, data: DocumentData):
    return await document_service.update(data.document_id, data)


@app.get("/reports/{report_id}")
async def render_report(report_service: ReportService, report_id: str):
    return await report_service.update_cache(report_id)


@app.patch("/secure/{record_id}", dependencies=[Depends(require_auth)])
async def update_secure_record(record_service: RecordService, record_id: str):
    return await record_service.update(record_id)
