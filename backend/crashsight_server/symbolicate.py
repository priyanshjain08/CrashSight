"""Symbolication via GNU binutils (readelf, addr2line) for ELF/DWARF on Linux.

Safety: symbol files are only ever *read* by readelf/addr2line, never executed.
Subprocesses use argument lists (no shell). Symbols are matched strictly by ELF
GNU build-id; a file whose build-id differs from the module's is never used.
Windows/PDB is NOT implemented.
"""
import os
import re
import subprocess
import threading

ELF_MAGIC = b"\x7fELF"
_BUILD_ID_RE = re.compile(r"Build ID:\s*([0-9a-f]+)")


class SymbolError(Exception):
    pass


def elf_build_id(path):
    """Return the GNU build-id of an ELF file or raise SymbolError."""
    with open(path, "rb") as f:
        if f.read(4) != ELF_MAGIC:
            raise SymbolError("not an ELF file")
    try:
        out = subprocess.run(["readelf", "-n", path], capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise SymbolError(f"readelf failed: {e}")
    m = _BUILD_ID_RE.search(out.stdout)
    if not m:
        raise SymbolError("ELF file has no GNU build-id (link with -Wl,--build-id)")
    return m.group(1)


def has_debug_info(path):
    out = subprocess.run(["readelf", "-S", path], capture_output=True, text=True, timeout=30, check=False)
    return ".debug_info" in out.stdout or ".symtab" in out.stdout


class SymbolStore:
    """Directory of symbol files keyed by build-id, with a result cache."""

    def __init__(self, root):
        self.root = os.path.abspath(root)
        os.makedirs(self.root, exist_ok=True)
        self._cache = {}
        self._lock = threading.Lock()
        self.cache_hits = 0
        self.cache_misses = 0

    def path_for(self, build_id):
        if not re.fullmatch(r"[0-9a-f]{8,128}", build_id or ""):
            raise SymbolError("invalid build id")
        p = os.path.join(self.root, build_id + ".sym")
        if os.path.dirname(os.path.abspath(p)) != self.root:  # path traversal guard
            raise SymbolError("invalid path")
        return p

    def register(self, data, claimed_build_id=None):
        """Store a symbol file. Returns (build_id, has_debug_info). Rejects mismatches."""
        if not data.startswith(ELF_MAGIC):
            raise SymbolError("symbol file is not an ELF file")
        tmp = os.path.join(self.root, ".upload-%d-%d.tmp" % (os.getpid(), threading.get_ident()))
        with open(tmp, "wb") as f:
            f.write(data)
        try:
            actual = elf_build_id(tmp)
            if claimed_build_id and claimed_build_id != actual:
                raise SymbolError(f"build-id mismatch: claimed {claimed_build_id}, file has {actual}")
            dbg = has_debug_info(tmp)
            os.replace(tmp, self.path_for(actual))
            with self._lock:
                self._cache = {k: v for k, v in self._cache.items() if k[0] != actual}
            return actual, dbg
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

    def has(self, build_id):
        try:
            return os.path.exists(self.path_for(build_id))
        except SymbolError:
            return False

    def resolve(self, build_id, module_offset, is_return_address):
        """Resolve one frame. Returns dict with status in:
        symbolicated | unresolved_no_symbols | unresolved_no_match | error."""
        if not build_id:
            return {"status": "unresolved_no_match", "detail": "module has no build id"}
        if not self.has(build_id):
            return {"status": "unresolved_no_symbols", "detail": "no symbol file registered for build id"}
        lookup = module_offset - 1 if (is_return_address and module_offset > 0) else module_offset
        key = (build_id, lookup)
        with self._lock:
            if key in self._cache:
                self.cache_hits += 1
                return dict(self._cache[key])
            self.cache_misses += 1
        try:
            out = subprocess.run(
                ["addr2line", "-e", self.path_for(build_id), "-f", "-C", "0x%x" % lookup],
                capture_output=True, text=True, timeout=30, check=False)
        except (OSError, subprocess.TimeoutExpired) as e:
            return {"status": "error", "detail": f"addr2line failed: {e}"}
        lines = out.stdout.strip().splitlines()
        if len(lines) < 2 or lines[0] == "??":
            res = {"status": "unresolved_no_symbols", "detail": "address not found in symbol file"}
        else:
            fn = lines[0]
            file_line = lines[1]
            src, line = None, None
            if not file_line.startswith("??"):
                m = re.match(r"^(.*?):(\d+|\?)(?:\s.*)?$", file_line)
                if m:
                    src = m.group(1)
                    line = int(m.group(2)) if m.group(2).isdigit() else None
            res = {"status": "symbolicated", "function": fn, "source_file": src, "line": line}
        with self._lock:
            self._cache[key] = res
        return dict(res)
