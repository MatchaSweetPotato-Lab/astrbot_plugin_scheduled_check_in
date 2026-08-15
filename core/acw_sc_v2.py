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
_IDENTIFIER = r"[A-Za-z_$][A-Za-z0-9_$]*"
_ARRAY_ASSIGN_RE = re.compile(
    rf"(?:\bvar\s+|[,;])\s*(?P<name>{_IDENTIFIER})\s*=\s*\[(?P<body>[^\[\]]+)\]"
)
_REORDER_FLOW_RE = re.compile(
    rf"(?P<permutation>{_IDENTIFIER})\s*\[\s*(?P<slot>{_IDENTIFIER})\s*\]"
    rf"\s*={{2,3}}\s*(?P<source_index>{_IDENTIFIER})\s*\+\s*(?:0x)?1"
    rf"\s*&&\s*\(?\s*(?P<buffer>{_IDENTIFIER})"
    rf"\s*\[\s*(?P=slot)\s*\]\s*=\s*(?P<character>{_IDENTIFIER})\s*\)?",
    re.DOTALL,
)
_HEX_OPERAND = (
    rf"parseInt\s*\(\s*(?P<%s>{_IDENTIFIER})\s*"
    rf"(?:\[[^\]]+\]|\.\s*{_IDENTIFIER})\s*\([^)]{{1,200}}\)"
    r"\s*,\s*(?:0x10|16)\s*\)"
)
_HEX_XOR_OPERANDS_RE = re.compile(
    (_HEX_OPERAND % "left")
    + r"\s*\^\s*"
    + (_HEX_OPERAND % "right"),
    re.DOTALL,
)
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


def _extract_permutation_assignments(script: str) -> dict[str, tuple[int, ...]]:
    """Return valid permutation arrays keyed by their JavaScript variable name."""
    assignments: dict[str, tuple[int, ...]] = {}
    for match in _ARRAY_ASSIGN_RE.finditer(script):
        raw_items = match.group("body").split(",")
        if len(raw_items) != 40:
            continue
        try:
            values = tuple(int(item.strip(), 0) for item in raw_items)
        except ValueError:
            continue
        if sorted(values) == list(range(1, 41)):
            assignments[match.group("name")] = values
    return assignments


def _extract_algorithm_dataflow(script: str) -> tuple[tuple[int, ...], str]:
    """Tie the permutation and XOR-key operand to the cookie-producing flow."""
    permutations = _extract_permutation_assignments(script)
    candidates: list[tuple[tuple[int, ...], str]] = []

    for flow_match in _REORDER_FLOW_RE.finditer(script):
        permutation_name = flow_match.group("permutation")
        permutation = permutations.get(permutation_name)
        if permutation is None:
            continue

        character = re.escape(flow_match.group("character"))
        source_index = re.escape(flow_match.group("source_index"))
        source_pattern = re.compile(
            rf"(?:\bvar\s+|,)\s*{character}\s*=\s*arg1"
            rf"\s*\[\s*{source_index}\s*\]"
        )
        flow_prefix = script[max(0, flow_match.start() - 500) : flow_match.start()]
        if source_pattern.search(flow_prefix) is None:
            continue

        buffer_name = re.escape(flow_match.group("buffer"))
        flow_suffix = script[flow_match.end() : flow_match.end() + 3000]
        join_pattern = re.compile(
            rf"\b(?P<joined>{_IDENTIFIER})\s*=\s*{buffer_name}\s*"
            rf"(?:\[[^\]]+\]|\.\s*join)\s*\(\s*"
            rf"(?P<quote>['\"])(?P=quote)\s*\)"
        )
        join_match = join_pattern.search(flow_suffix)
        if join_match is None:
            continue

        xor_region = flow_suffix[join_match.end() :]
        xor_match = _HEX_XOR_OPERANDS_RE.search(xor_region)
        if xor_match is None:
            continue
        joined_name = join_match.group("joined")
        operands = (xor_match.group("left"), xor_match.group("right"))
        if operands.count(joined_name) != 1:
            continue
        key_name = operands[1] if operands[0] == joined_name else operands[0]

        byte_prefix = xor_region[max(0, xor_match.start() - 100) : xor_match.start()]
        byte_match = re.search(
            rf"(?:\bvar\s+)?(?P<byte>{_IDENTIFIER})\s*=\s*\(\s*$",
            byte_prefix,
        )
        if byte_match is None:
            continue
        byte_name = re.escape(byte_match.group("byte"))
        xor_suffix = xor_region[xor_match.end() : xor_match.end() + 1200]
        accumulator_match = re.search(
            rf"\b(?P<accumulator>{_IDENTIFIER})\s*\+=\s*{byte_name}\b",
            xor_suffix,
        )
        if accumulator_match is None:
            continue
        accumulator = re.escape(accumulator_match.group("accumulator"))
        cookie_suffix = xor_suffix[accumulator_match.end() :]
        if re.search(
            rf"['\"]{re.escape(_COOKIE_NAME)}=['\"]\s*\+\s*{accumulator}\b",
            cookie_suffix,
        ) is None:
            continue

        key_assignments = list(
            re.finditer(
                rf"(?:\bvar\s+|,)\s*{re.escape(key_name)}\s*=\s*"
                rf"(?P<expression>{_IDENTIFIER}\s*\([^;)]*\)|['\"][^'\"]+['\"])",
                script[: flow_match.end()],
            )
        )
        if not key_assignments:
            continue
        key_assignment = key_assignments[-1]
        candidates.append((permutation, key_assignment.group("expression")))

    if len(candidates) != 1:
        raise AcwScV2Error("无法唯一确认生成 acw_sc__v2 的字符重排与 XOR 数据流")
    return candidates[0]


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


def _xor_key_candidates(
    values: list[str],
    alphabets: list[str],
    arg1: str,
) -> set[str]:
    candidates: set[str] = set()
    for value in values:
        if value != arg1 and _HEX_40_RE.fullmatch(value):
            candidates.add(value.lower())
        for alphabet in alphabets:
            decoded = _decode_custom_base64(value, alphabet)
            if decoded and decoded != arg1 and _HEX_40_RE.fullmatch(decoded):
                candidates.add(decoded.lower())
    return candidates


def _extract_xor_key(script: str, arg1: str, key_expression: str) -> str:
    strings = _iter_js_strings(script)
    alphabets = _extract_base64_alphabets(strings)

    expression_candidates = _xor_key_candidates(
        _iter_js_strings(key_expression),
        alphabets,
        arg1,
    )
    if len(expression_candidates) == 1:
        return expression_candidates.pop()
    if len(expression_candidates) > 1:
        raise AcwScV2Error("XOR 操作数表达式包含多个候选密钥")

    decoder_call = re.fullmatch(
        rf"\s*(?P<callee>{_IDENTIFIER})\s*\([^)]*\)\s*",
        key_expression,
    )
    if decoder_call is None:
        raise AcwScV2Error("XOR 操作数不是可验证的字符串或解码器调用")

    decoder_name = decoder_call.group("callee")
    alias_match = re.search(
        rf"(?:\bvar\s+|,)\s*{re.escape(decoder_name)}\s*=\s*"
        rf"(?P<target>{_IDENTIFIER})\b",
        script,
    )
    decoder_target = alias_match.group("target") if alias_match else decoder_name
    function_match = re.search(
        rf"\bfunction\s+{re.escape(decoder_target)}\s*\(",
        script,
    )
    if function_match is None:
        raise AcwScV2Error("无法确认 XOR 密钥解码器")
    next_function = re.search(r"\bfunction\s+[A-Za-z_$]", script[function_match.end() :])
    function_end = (
        function_match.end() + next_function.start()
        if next_function is not None
        else len(script)
    )
    decoder_source = script[function_match.start() : function_end]
    if not any(alphabet in decoder_source for alphabet in alphabets):
        raise AcwScV2Error("XOR 密钥解码器缺少可验证的 Base64 字母表")

    candidates = _xor_key_candidates(strings, alphabets, arg1)
    if len(candidates) != 1:
        raise AcwScV2Error("无法从 XOR 解码器唯一确认 40 位密钥")
    return candidates.pop()


def translate_acw_sc_v2(script: str) -> tuple[str, AcwScV2Algorithm, str]:
    """Translate an inline JavaScript challenge to deterministic Python source.

    Returns:
        Tuple of ``(arg1, algorithm, python_source)``.
    """
    if _COOKIE_NAME not in script.lower():
        raise AcwScV2Error("响应不是 acw_sc__v2 挑战")

    arg1 = _extract_arg1(script)
    permutation, key_expression = _extract_algorithm_dataflow(script)
    algorithm = AcwScV2Algorithm(
        permutation=permutation,
        xor_key=_extract_xor_key(script, arg1, key_expression),
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
