"""Errors that mean "nothing may leave the machine".

Every stage of the pipeline raises a subclass of `FailClosedError` instead of degrading: a caller
(CLI, proxy) catches this one type and refuses to send anything. Messages never contain values.
"""


class FailClosedError(RuntimeError):
    """The input must not be sent to the model."""
