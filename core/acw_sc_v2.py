"""Pure-Python translator and solver for Aliyun ``acw_sc__v2`` challenges.

The challenge page contains a JavaScript implementation of a permutation plus
hexadecimal XOR operation.  This module extracts that algorithm, emits an
equivalent Python function, caches the emitted source by an algorithm
fingerprint, and executes it with the running Python interpreter.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from types import FunctionType
from typing import Any

logger = logging.getLogger("astrbot")

_CACHE_VERSION = 1
_COOKIE_NAME = "acw_sc__v2"
_HEX_40_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_ARG1_RE = re.compile(
    r"\barg1\s*=\s*(?P<quote>['\"])(?P<value>[0-9a-fA-F]{40})(?P=quote)",
    re.IGNORECASE,
)
_HEX_XOR_RE = re.compile(
    r"parseInt\s*\([^;]{1,500}?\)\s*\^\s*parseInt\s*\(",
    re.DOTALL,
)
_ARRAY_RE = re.compile(r"\[([^\[\]]+)\]")
_JS_STRING_RE = re.compile(
    r"(?P<quote>['\"])(?P<body>(?:\\.|(?!\1).)*)(?P=quote)",
    re.DOTALL,
)
_STANDARD_BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
_KNOWN_CUSTOM_BASE64_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
_CACHE_LOCK = Lock()


class AcwScV2Error(ValueError):
    """Raised when an ``acw_sc__v2`` challenge cannot be translated or solved."""


@dataclass(frozen=True)
class AcwScV2Algorithm:
    """Validated constants recovered from the JavaScript challenge."""

    permutation: tuple[int, ...]
    xor_key: str

    @property
    def fingerprint(self) -> str:
        """Return a stable fingerprint of the effective algorithm."""
        canonical = json.dumps(
            {
                "kind": "permute_then_hex_xor",
                "permutation": self.permutation,
                "xor_key": self.xor_key.lower(),
            },
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AcwScV2Solution:
    """Solved cookie value and translation metadata."""

    cookie_value: str
    algorithm_fingerprint: str
    cache_hit: bool


def is_acw_sc_v2_challenge(response_text: str) -> bool:
    """Return whether a response contains an inline v2 JavaScript challenge."""
    lower_text = response_text.lower()
    return (
        _COOKIE_NAME in lower_text
        and "<script" in lower_text
        and _ARG1_RE.search(response_text) is not None
    )


def _extract_arg1(script: str) -> str:
    match = _ARG1_RE.search(script)
    if not match:
        raise AcwScV2Error("挑战脚本缺少 40 位 arg1")
    return match.group("value")


def _extract_permutation(script: str) -> tuple[int, ...]:
    for match in _ARRAY_RE.finditer(script):
        raw_items = match.group(1).split(",")
        if len(raw_items) != 40:
            continue
        try:
            values = tuple(int(item.strip(), 0) for item in raw_items)
        except ValueError:
            continue
        if sorted(values) == list(range(1, 41)):
            return values
    raise AcwScV2Error("挑战脚本缺少有效的 40 项字符重排表")


def _iter_js_strings(script: str) -> list[str]:
    return [match.group("body") for match in _JS_STRING_RE.finditer(script)]


def _extract_base64_alphabets(strings: list[str]) -> list[str]:
    alphabets = [_KNOWN_CUSTOM_BASE64_ALPHABET, _STANDARD_BASE64_ALPHABET]
    for value in strings:
        if (
            len(value) == 65
            and value.endswith("=")
            and len(set(value[:-1])) == 64
            and set(value[:-1]) == set(_STANDARD_BASE64_ALPHABET[:-1])
            and value not in alphabets
        ):
            alphabets.insert(0, value)
    return alphabets


def _decode_custom_base64(value: str, alphabet: str) -> str | None:
    if not value or any(char not in alphabet for char in value):
        return None
    translated = value.translate(str.maketrans(alphabet, _STANDARD_BASE64_ALPHABET))
    translated += "=" * (-len(translated) % 4)
    try:
        return base64.b64decode(translated, validate=False).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None


def _extract_xor_key(script: str, arg1: str) -> str:
    strings = _iter_js_strings(script)

    for value in strings:
        if value != arg1 and _HEX_40_RE.fullmatch(value):
            return value.lower()

    for alphabet in _extract_base64_alphabets(strings):
        for value in strings:
            decoded = _decode_custom_base64(value, alphabet)
            if decoded and decoded != arg1 and _HEX_40_RE.fullmatch(decoded):
                return decoded.lower()

    raise AcwScV2Error("挑战脚本缺少可识别的 40 位 XOR 密钥")


def translate_acw_sc_v2(script: str) -> tuple[str, AcwScV2Algorithm, str]:
    """Translate an inline JavaScript challenge to deterministic Python source.

    Returns:
        Tuple of ``(arg1, algorithm, python_source)``.
    """
    if _COOKIE_NAME not in script.lower():
        raise AcwScV2Error("响应不是 acw_sc__v2 挑战")
    if _HEX_XOR_RE.search(script) is None:
        raise AcwScV2Error("挑战脚本不是受支持的十六进制 XOR 算法")

    arg1 = _extract_arg1(script)
    algorithm = AcwScV2Algorithm(
        permutation=_extract_permutation(script),
        xor_key=_extract_xor_key(script, arg1),
    )
    return arg1, algorithm, build_python_source(algorithm)


def build_python_source(algorithm: AcwScV2Algorithm) -> str:
    """Emit a self-contained Python implementation for a validated algorithm."""
    permutation = repr(algorithm.permutation)
    xor_key = repr(algorithm.xor_key.lower())
    return (
        "def solve_acw_sc_v2(arg1):\n"
        f"    permutation = {permutation}\n"
        f"    xor_key = {xor_key}\n"
        "    if not isinstance(arg1, str) or len(arg1) != 40:\n"
        "        raise ValueError('arg1 must be a 40-character hexadecimal string')\n"
        "    try:\n"
        "        int(arg1, 16)\n"
        "    except ValueError as exc:\n"
        "        raise ValueError('arg1 must be a 40-character hexadecimal string') from exc\n"
        "    reordered = ''.join(arg1[position - 1] for position in permutation)\n"
        "    return ''.join(\n"
        "        f'{int(reordered[index:index + 2], 16) ^ int(xor_key[index:index + 2], 16):02x}'\n"
        "        for index in range(0, 40, 2)\n"
        "    )\n"
    )


def _compile_solver(source: str, fingerprint: str) -> Callable[[str], str]:
    allowed_builtins = {
        "ValueError": ValueError,
        "int": int,
        "isinstance": isinstance,
        "len": len,
        "range": range,
        "str": str,
    }
    namespace: dict[str, Any] = {}
    exec(
        compile(source, f"<acw_sc__v2:{fingerprint[:12]}>", "exec"),
        {"__builtins__": allowed_builtins},
        namespace,
    )
    solver = namespace.get("solve_acw_sc_v2")
    if not isinstance(solver, FunctionType):
        raise AcwScV2Error("缓存的 Python 转换结果无有效入口函数")
    return solver


class AcwScV2SolverCache:
    """Translate, cache, compile, and execute ``acw_sc__v2`` algorithms."""

    def __init__(self, cache_file: Path | None = None) -> None:
        self.cache_file = Path(cache_file) if cache_file else None
        self._compiled: dict[str, Callable[[str], str]] = {}

    def solve(self, challenge_html: str) -> AcwScV2Solution:
        """Solve a challenge, reusing cached Python source when possible."""
        arg1, algorithm, generated_source = translate_acw_sc_v2(challenge_html)
        fingerprint = algorithm.fingerprint
        cached_source = self._read_cached_source(fingerprint)
        if cached_source is not None and cached_source == generated_source:
            cache_hit = True
            source = cached_source
        else:
            cache_hit = False
            source = generated_source

        if not cache_hit:
            self._write_cached_source(
                fingerprint,
                algorithm,
                source,
                replace=cached_source is not None,
            )

        solver = self._compiled.get(fingerprint)
        if solver is None:
            solver = _compile_solver(source, fingerprint)
            self._compiled[fingerprint] = solver

        cookie_value = solver(arg1)
        if not _HEX_40_RE.fullmatch(cookie_value):
            raise AcwScV2Error("Python 解算结果不是有效的 40 位十六进制值")
        return AcwScV2Solution(
            cookie_value=cookie_value.lower(),
            algorithm_fingerprint=fingerprint,
            cache_hit=cache_hit,
        )

    def _load_cache(self) -> dict[str, Any]:
        if not self.cache_file or not self.cache_file.exists():
            return {"version": _CACHE_VERSION, "algorithms": {}}
        try:
            data = json.loads(self.cache_file.read_text(encoding="utf-8"))
            if data.get("version") != _CACHE_VERSION or not isinstance(data.get("algorithms"), dict):
                return {"version": _CACHE_VERSION, "algorithms": {}}
            return data
        except (OSError, ValueError, AttributeError) as exc:
            logger.warning("Failed to read acw_sc__v2 cache %s: %s", self.cache_file, exc)
            return {"version": _CACHE_VERSION, "algorithms": {}}

    def _read_cached_source(self, fingerprint: str) -> str | None:
        if not self.cache_file:
            return None
        with _CACHE_LOCK:
            entry = self._load_cache().get("algorithms", {}).get(fingerprint)
        if not isinstance(entry, dict):
            return None
        source = entry.get("python_source")
        return source if isinstance(source, str) and source.strip() else None

    def _write_cached_source(
        self,
        fingerprint: str,
        algorithm: AcwScV2Algorithm,
        source: str,
        replace: bool = False,
    ) -> None:
        if not self.cache_file:
            return

        with _CACHE_LOCK:
            data = self._load_cache()
            algorithms = data.setdefault("algorithms", {})
            if fingerprint in algorithms and not replace:
                return

            algorithms[fingerprint] = {
                "algorithm": "permute_then_hex_xor",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "permutation": list(algorithm.permutation),
                "xor_key": algorithm.xor_key,
                "python_source": source,
            }

            try:
                self.cache_file.parent.mkdir(parents=True, exist_ok=True)
                temp_file = self.cache_file.with_suffix(self.cache_file.suffix + ".tmp")
                temp_file.write_text(
                    json.dumps(data, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
                temp_file.replace(self.cache_file)
            except OSError as exc:
                logger.warning("Failed to write acw_sc__v2 cache %s: %s", self.cache_file, exc)
