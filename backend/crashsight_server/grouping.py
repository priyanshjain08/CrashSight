"""Crash signature computation. Signature algorithm version 1.

Raw addresses are never used (ASLR). Each considered frame is keyed by its
symbolicated function name when available, else by module basename + module
offset (stable across runs of the same build, NOT across different builds).
Frames from system libraries are skipped so unrelated libc internals do not
dominate the signature. Version the algorithm: changing it requires bumping
SIGNATURE_VERSION so old groups are not silently reinterpreted.
"""
import hashlib
import os

SIGNATURE_VERSION = 1
TOP_FRAMES = 5
_SYSTEM_PREFIXES = ("/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/")


def is_app_frame(module):
    if not module or module.startswith("linux-vdso") or module.startswith("[vdso]"):
        return False
    return not module.startswith(_SYSTEM_PREFIXES)


def frame_key(frame):
    if frame.get("status") == "symbolicated" and frame.get("function"):
        return "fn:" + frame["function"]
    return "mod:%s+0x%x" % (os.path.basename(frame.get("module", "")) or "?", frame.get("module_offset", 0))


def compute_signature(crash_type, frames):
    """frames: list of dicts with module, module_offset, status, function.
    Returns (signature_hex, explanation, title)."""
    chosen = [f for f in frames if is_app_frame(f.get("module"))][:TOP_FRAMES]
    basis = "application frames"
    if not chosen:
        chosen = frames[:3]
        basis = "first frames (no application frames found)"
    keys = [frame_key(f) for f in chosen]
    payload = "v%d|%s|%s" % (SIGNATURE_VERSION, crash_type, "|".join(keys))
    sig = hashlib.sha256(payload.encode()).hexdigest()
    explanation = "signature v%d: %s + %d %s: %s" % (
        SIGNATURE_VERSION, crash_type, len(keys), basis, " <- ".join(keys) if keys else "(none)")
    top = keys[0] if keys else "no stack"
    title = "%s in %s" % (crash_type, top.split(":", 1)[-1])
    return sig, explanation, title
