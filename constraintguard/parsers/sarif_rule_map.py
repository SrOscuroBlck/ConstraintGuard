from constraintguard.models.enums import VulnerabilityCategory

_RULE_CATEGORY_MAP: dict[str, VulnerabilityCategory] = {
    # --- Buffer overflow / out-of-bounds ---
    "alpha.security.ArrayBoundV2": VulnerabilityCategory.BUFFER_OVERFLOW,
    "alpha.security.ReturnPtrRange": VulnerabilityCategory.BUFFER_OVERFLOW,
    "alpha.unix.cstring.OutOfBounds": VulnerabilityCategory.BUFFER_OVERFLOW,
    "alpha.unix.cstring.BufferOverlap": VulnerabilityCategory.BUFFER_OVERFLOW,
    "security.insecureAPI.strcpy": VulnerabilityCategory.BUFFER_OVERFLOW,
    "security.insecureAPI.strcat": VulnerabilityCategory.BUFFER_OVERFLOW,
    "security.insecureAPI.gets": VulnerabilityCategory.BUFFER_OVERFLOW,
    "security.insecureAPI.sprintf": VulnerabilityCategory.BUFFER_OVERFLOW,
    "security.insecureAPI.vsprintf": VulnerabilityCategory.BUFFER_OVERFLOW,
    "security.insecureAPI.scanf": VulnerabilityCategory.BUFFER_OVERFLOW,
    "security.insecureAPI.strncat": VulnerabilityCategory.BUFFER_OVERFLOW,
    # --- Null dereference ---
    "core.NullDereference": VulnerabilityCategory.NULL_DEREF,
    "alpha.core.CastToStruct": VulnerabilityCategory.NULL_DEREF,
    "alpha.core.NullDereference": VulnerabilityCategory.NULL_DEREF,
    # --- Memory leaks ---
    "unix.Malloc": VulnerabilityCategory.LEAK,
    "cplusplus.NewDeleteLeaks": VulnerabilityCategory.LEAK,
    "alpha.unix.MallocWithAnnotations": VulnerabilityCategory.LEAK,
    "alpha.cplusplus.MismatchedIterator": VulnerabilityCategory.LEAK,
    # --- Use-after-free / double-free ---
    "cplusplus.NewDelete": VulnerabilityCategory.USE_AFTER_FREE,
    "unix.MismatchedDeallocator": VulnerabilityCategory.USE_AFTER_FREE,
    "alpha.cplusplus.DeleteWithNonVirtualDtor": VulnerabilityCategory.USE_AFTER_FREE,
    # --- Integer overflow / taint ---
    "alpha.security.taint.TaintPropagation": VulnerabilityCategory.INTEGER_OVERFLOW,
    "alpha.security.taint.TaintPropagationChecker": VulnerabilityCategory.INTEGER_OVERFLOW,
    # --- Format string ---
    "security.insecureAPI.vfprintf": VulnerabilityCategory.FORMAT_STRING,
    "security.insecureAPI.printf": VulnerabilityCategory.FORMAT_STRING,
    # --- Divide by zero ---
    "core.DivideZero": VulnerabilityCategory.DIVIDE_BY_ZERO,
    # --- Uninitialized values ---
    "core.uninitialized.Assign": VulnerabilityCategory.UNINITIALIZED,
    "core.uninitialized.Branch": VulnerabilityCategory.UNINITIALIZED,
    "core.uninitialized.CapturedBlockVariable": VulnerabilityCategory.UNINITIALIZED,
    "core.uninitialized.UndefReturn": VulnerabilityCategory.UNINITIALIZED,
    "core.uninitialized.ArraySubscript": VulnerabilityCategory.UNINITIALIZED,
    # --- Concurrency / deadlock ---
    "alpha.unix.PthreadLock": VulnerabilityCategory.DEADLOCK,
    "alpha.core.CastSize": VulnerabilityCategory.INTEGER_OVERFLOW,
}

_RULE_CWE_MAP: dict[str, str] = {
    # Buffer overflow
    "alpha.security.ArrayBoundV2": "CWE-119",
    "alpha.security.ReturnPtrRange": "CWE-119",
    "alpha.unix.cstring.OutOfBounds": "CWE-119",
    "alpha.unix.cstring.BufferOverlap": "CWE-119",
    "security.insecureAPI.strcpy": "CWE-120",
    "security.insecureAPI.strcat": "CWE-120",
    "security.insecureAPI.gets": "CWE-120",
    "security.insecureAPI.sprintf": "CWE-120",
    "security.insecureAPI.vsprintf": "CWE-120",
    "security.insecureAPI.scanf": "CWE-120",
    "security.insecureAPI.strncat": "CWE-120",
    # Null dereference
    "core.NullDereference": "CWE-476",
    "alpha.core.CastToStruct": "CWE-476",
    "alpha.core.NullDereference": "CWE-476",
    # Leaks
    "unix.Malloc": "CWE-401",
    "cplusplus.NewDeleteLeaks": "CWE-401",
    "alpha.unix.MallocWithAnnotations": "CWE-401",
    # Use-after-free
    "cplusplus.NewDelete": "CWE-416",
    "unix.MismatchedDeallocator": "CWE-416",
    # Taint / integer
    "alpha.security.taint.TaintPropagation": "CWE-190",
    "alpha.core.CastSize": "CWE-190",
    # Format string
    "security.insecureAPI.vfprintf": "CWE-134",
    "security.insecureAPI.printf": "CWE-134",
    # Divide by zero
    "core.DivideZero": "CWE-369",
    # Uninitialized
    "core.uninitialized.Assign": "CWE-457",
    "core.uninitialized.Branch": "CWE-457",
    "core.uninitialized.CapturedBlockVariable": "CWE-457",
    "core.uninitialized.UndefReturn": "CWE-457",
    "core.uninitialized.ArraySubscript": "CWE-457",
    # Deadlock
    "alpha.unix.PthreadLock": "CWE-833",
}

_CATEGORY_FALLBACK_CWE: dict[VulnerabilityCategory, str] = {
    VulnerabilityCategory.BUFFER_OVERFLOW: "CWE-120",
    VulnerabilityCategory.NULL_DEREF: "CWE-476",
    VulnerabilityCategory.LEAK: "CWE-401",
    VulnerabilityCategory.USE_AFTER_FREE: "CWE-416",
    VulnerabilityCategory.INTEGER_OVERFLOW: "CWE-190",
    VulnerabilityCategory.FORMAT_STRING: "CWE-134",
    VulnerabilityCategory.DIVIDE_BY_ZERO: "CWE-369",
    VulnerabilityCategory.UNINITIALIZED: "CWE-457",
    VulnerabilityCategory.DEADLOCK: "CWE-833",
}

_PREFIX_CATEGORY_MAP: list[tuple[str, VulnerabilityCategory]] = [
    ("core.uninitialized.", VulnerabilityCategory.UNINITIALIZED),
    ("alpha.security.taint.", VulnerabilityCategory.INTEGER_OVERFLOW),
    ("alpha.unix.cstring.", VulnerabilityCategory.BUFFER_OVERFLOW),
    ("security.insecureAPI.", VulnerabilityCategory.BUFFER_OVERFLOW),
    ("cplusplus.NewDelete", VulnerabilityCategory.USE_AFTER_FREE),
    ("unix.Malloc", VulnerabilityCategory.LEAK),
    ("alpha.unix.PthreadLock", VulnerabilityCategory.DEADLOCK),
]


def resolve_category(rule_id: str) -> VulnerabilityCategory:
    exact = _RULE_CATEGORY_MAP.get(rule_id)
    if exact is not None:
        return exact

    for prefix, category in _PREFIX_CATEGORY_MAP:
        if rule_id.startswith(prefix):
            return category

    return VulnerabilityCategory.UNKNOWN


def resolve_cwe(rule_id: str, category: VulnerabilityCategory | None = None) -> str | None:
    exact = _RULE_CWE_MAP.get(rule_id)
    if exact is not None:
        return exact

    if category is not None:
        return _CATEGORY_FALLBACK_CWE.get(category)

    return None
