class DatabaseValidationError(ValueError):
    """Raised when a normalized event cannot be safely persisted."""
