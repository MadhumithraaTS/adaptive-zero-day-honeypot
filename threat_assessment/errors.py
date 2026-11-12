class AssessmentConfigError(ValueError):
    """Attribution/policy configuration is missing, malformed, unverified or inconsistent. Nothing is assessed."""


class AssessmentInputError(ValueError):
    """An evidence record does not match the supported behavioural_evidence output contract."""
