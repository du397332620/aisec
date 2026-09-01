from uuid import uuid4


# Same class names in another module must not make qualified service models ambiguous.
class Profile:
    @staticmethod
    def id_generator() -> str:
        return str(uuid4())


class Payment(Profile):
    pass
