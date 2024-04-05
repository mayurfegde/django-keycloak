class APICallError(Exception):
    def __init__(self, message, status_code=None):
        self.message = message
        self.status_code = status_code
