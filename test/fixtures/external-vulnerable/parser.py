import pickle


def restore_session(payload):
    return pickle.loads(payload)
