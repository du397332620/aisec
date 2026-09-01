from uuid import UUID

from fastapi import FastAPI

from services import ObjectService, PaymentService, ProfileService, RefundService, SessionService, TokenService

app = FastAPI()


@app.patch("/profiles/{profile_id}")
async def update_profile(profile_service: ProfileService, profile_id: str, data: CustomerUpdateData):
    item = await profile_service.get(profile_id)
    kwargs = {field: value for field, value in data if not getattr(item, field) and value}
    if kwargs:
        item.update(**kwargs)
    return item


@app.patch("/payments/{payment_id}/address")
async def update_payment_address(payment_service: PaymentService, payment_id: str, data: PaymentAddressData):
    return await payment_service.update_payment_address(payment_id, data)


@app.post("/refunds/{refund_id}/submit")
async def submit_refund(refund_service: RefundService, refund_id: str, data: SubmitRefundData):
    return await refund_service.submit_refund(refund_id, data)


@app.delete("/sessions/{session_id}")
async def delete_session(session_service: SessionService, session_id: str):
    item = await session_service.get(session_id)
    await item.delete()
    return {"deleted": True}


@app.post("/tokens/{token_id}/rotate")
async def rotate_token(token_service: TokenService, token_id: str, data: RotateTokenData):
    return await token_service.rotate_token(token_id, data)


@app.patch("/workflows/{workflow_id}/approve")
async def approve_workflow(workflow_service: UnknownWorkflowService, workflow_id: UUID):
    return await workflow_service.approve(workflow_id)


@app.patch("/objects/{object_id}/set")
async def set_object_value(object_service: ObjectService, object_id: str, data: ValueData):
    return await object_service.set_value(object_id, data)
