class RemovedInPyjwt3Warning(DeprecationWarning):
    """Warning class to indicate functionality that will be removed in PyJWT version 3.

    This warning is a subclass of DeprecationWarning, which allows users to easily
    identify and handle warnings specific to upcoming changes in PyJWT version 3.
    """

    def __init__(self, message: str):
        super().__init__(message)
