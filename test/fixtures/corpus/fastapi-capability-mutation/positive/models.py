import secrets
from uuid import uuid4

import common


class IDModel:
    @staticmethod
    def id_generator() -> str:
        return common.unique_id()


class RecordModel(IDModel):
    pass


class Profile(RecordModel):
    pass


class Payment(RecordModel):
    pass


class Refund(RecordModel):
    pass


class Session:
    @staticmethod
    def id_generator() -> str:
        return str(uuid4())


class Token:
    @staticmethod
    def id_generator() -> str:
        return secrets.token_urlsafe(32)


class Decoy:
    @staticmethod
    def id_generator() -> str:
        # return ULID()
        example = "secrets.token_urlsafe(32)"
        return external_id(example)
