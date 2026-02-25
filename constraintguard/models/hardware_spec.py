from pydantic import BaseModel, Field

from constraintguard.models.enums import ConstraintSourceType


class FieldProvenance(BaseModel):
    source_type: ConstraintSourceType
    source_path: str | None = None
    extraction_note: str | None = None


class ConstraintProvenance(BaseModel):
    field_origins: dict[str, FieldProvenance] = Field(default_factory=dict)


class HardwareSpec(BaseModel):
    platform: str | None = None
    ram_size_bytes: int | None = None
    flash_size_bytes: int | None = None
    stack_size_bytes: int | None = None
    heap_size_bytes: int | None = None
    max_interrupt_latency_us: int | None = None
    critical_functions: list[str] = Field(default_factory=list)
    safety_level: str | None = None
