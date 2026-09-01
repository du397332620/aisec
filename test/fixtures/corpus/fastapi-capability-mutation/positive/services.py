from fastapi import HTTPException

import models


class CRUDService[T]:
    async def get(self, item_id: str, **kwargs):
        return object()


class ProfileService(CRUDService[models.Profile]):
    pass


class PaymentService(CRUDService[models.Payment]):
    async def update_payment_address(self, payment_id: str, data):
        item = await self.get(payment_id)
        if item.status != PaymentStatus.PENDING:
            raise HTTPException(422, "state does not allow changes")
        if item.user_address is not None:
            raise HTTPException(422, "address already set")
        item.update(user_address=data.address)
        return item


class RefundService(CRUDService[models.Refund]):
    async def submit_refund(self, refund_id: str, data):
        refund = await self.get(refund_id, atomic_update=True)
        if refund.payout_id:
            raise HTTPException(422, "already submitted")
        payout = await self.create_payout(destination=data.destination)
        refund.update(payout=payout, destination=data.destination)
        return refund


class SessionService(CRUDService[models.Session]):
    pass


class TokenService(CRUDService[models.Token]):
    async def rotate_token(self, token_id: str, data):
        token = await self.get(token_id)
        if token.expires_at < now():
            raise HTTPException(410, "expired")
        token.update(value=data.value)
        return token


class ObjectService(CRUDService[models.Decoy]):
    pass
