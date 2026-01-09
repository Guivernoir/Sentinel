"""
Custom exceptions for Sentinel operations.
Because sys.exit(1) in a library is a war crime.
"""


class SentinelException(Exception):
    """
    Base exception for all Sentinel operations.
    The foundation of civilized error handling.
    """
    pass


class AnalysisTimeout(SentinelException):
    """
    Raised when analysis request times out.
    The target wasn't responsive enough for intelligence gathering.
    """
    pass


class ConnectionFailed(SentinelException):
    """
    Raised when connection to target cannot be established.
    The network betrayed us, or the target doesn't exist.
    """
    pass


class InvalidConfiguration(SentinelException):
    """
    Raised when analyzer configuration is invalid.
    Someone tried to deploy with broken parameters.
    """
    pass


class ParseError(SentinelException):
    """
    Raised when header parsing fails catastrophically.
    The server sent something that offends the specification.
    """
    pass