"""Report schema validation (schema v1). Defensive: bounded sizes, strict types,
unknown fields ignored, newer major versions rejected."""
import re

CURRENT_SCHEMA = 1
MAX_REPORT_BYTES = 1 << 20
MAX_FRAMES = 128
MAX_MODULES = 256
MAX_CONTEXT = 32

_ID = re.compile(r"^[0-9a-fA-F-]{8,64}$")
_HEX = re.compile(r"^0x[0-9a-fA-F]{1,16}$")
_BUILD = re.compile(r"^[0-9a-f]{0,128}$")


class ValidationError(ValueError):
    pass


def _s(d, key, maxlen, required=False):
    v = d.get(key, "")
    if v is None:
        v = ""
    if not isinstance(v, str):
        raise ValidationError(f"{key} must be a string")
    if required and not v:
        raise ValidationError(f"{key} is required")
    if len(v) > maxlen:
        raise ValidationError(f"{key} too long")
    return v


def _hex(v, name):
    if not isinstance(v, str) or not _HEX.match(v):
        raise ValidationError(f"{name} must be a hex address like 0x1234")
    return int(v, 16)


def validate_report(doc):
    """Return a normalized dict or raise ValidationError."""
    if not isinstance(doc, dict):
        raise ValidationError("report must be a JSON object")
    ver = doc.get("schema_version")
    if not isinstance(ver, int) or isinstance(ver, bool):
        raise ValidationError("schema_version must be an integer")
    if ver < 1 or ver > CURRENT_SCHEMA:
        raise ValidationError(f"unsupported schema_version {ver}")
    rid = _s(doc, "report_id", 64, True)
    if not _ID.match(rid):
        raise ValidationError("report_id malformed")
    kind = _s(doc, "kind", 16, True)
    if kind not in ("fatal", "diagnostic"):
        raise ValidationError("kind must be fatal or diagnostic")

    frames = doc.get("frames", [])
    if not isinstance(frames, list) or len(frames) > MAX_FRAMES:
        raise ValidationError("frames must be a list of at most %d" % MAX_FRAMES)
    nframes = []
    for f in frames:
        if not isinstance(f, dict):
            raise ValidationError("frame must be an object")
        nframes.append({
            "address": _hex(f.get("address"), "frame.address"),
            "module": _s(f, "module", 512),
            "module_offset": _hex(f.get("module_offset", "0x0"), "frame.module_offset"),
        })

    modules = doc.get("modules", [])
    if not isinstance(modules, list) or len(modules) > MAX_MODULES:
        raise ValidationError("modules must be a list of at most %d" % MAX_MODULES)
    nmods = []
    for m in modules:
        if not isinstance(m, dict):
            raise ValidationError("module must be an object")
        bid = _s(m, "build_id", 128)
        if not _BUILD.match(bid):
            raise ValidationError("module.build_id must be lowercase hex")
        nmods.append({"name": _s(m, "name", 512), "base": _hex(m.get("base", "0x0"), "module.base"), "build_id": bid})

    ctx = doc.get("context", {})
    if not isinstance(ctx, dict) or len(ctx) > MAX_CONTEXT:
        raise ValidationError("context must be an object with at most %d entries" % MAX_CONTEXT)
    nctx = {}
    for k, v in ctx.items():
        if not isinstance(k, str) or not isinstance(v, str) or len(k) > 64 or len(v) > 256:
            raise ValidationError("context entries must be short strings")
        nctx[k] = v

    sig = doc.get("signal_or_code", 0)
    if not isinstance(sig, int) or isinstance(sig, bool):
        raise ValidationError("signal_or_code must be an integer")

    return {
        "schema_version": ver,
        "report_id": rid,
        "sdk_version": _s(doc, "sdk_version", 32),
        "kind": kind,
        "application_name": _s(doc, "application_name", 128, True),
        "application_version": _s(doc, "application_version", 64, True),
        "environment": _s(doc, "environment", 64),
        "build_id": _s(doc, "build_id", 128),
        "os": _s(doc, "os", 64),
        "architecture": _s(doc, "architecture", 32),
        "timestamp_utc": _s(doc, "timestamp_utc", 32),
        "crash_type": _s(doc, "crash_type", 32, True),
        "signal_or_code": sig,
        "fault_address": _hex(doc.get("fault_address", "0x0"), "fault_address"),
        "process_id": int(doc.get("process_id", 0)) if isinstance(doc.get("process_id", 0), int) else 0,
        "thread_id": int(doc.get("thread_id", 0)) if isinstance(doc.get("thread_id", 0), int) else 0,
        "message": _s(doc, "message", 1024),
        "frames": nframes,
        "modules": nmods,
        "context": nctx,
        "capture_method": _s(doc, "capture_method", 64),
        "capture_limitations": _s(doc, "capture_limitations", 512),
    }
