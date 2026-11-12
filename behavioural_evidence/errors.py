"""Loud failure types: the framework never substitutes missing telemetry or legacy features."""


class SchemaError(ValueError):
    """Input telemetry is missing a required field or declares an unsupported schema version."""


class CatalogueError(ValueError):
    """The indicator catalogue (or a calibration file) is incompatible with this implementation."""


class AttributionError(ValueError):
    """A rule that needs source attribution received events without any source field."""
