"""Static code scanner (ported from ``core/sandbox.py``).

When a request carries a *code* payload — something an agent is about to
``exec`` or write to disk and run — this module scans it for dangerous
constructs using two complementary passes:

* an **AST pass** that understands Python structure (calls to ``eval``/``exec``,
  ``subprocess``, ``os.system``, dynamic ``__import__`` / ``getattr`` obfuscation,
  attribute chains that reach ``os``/``sys``), and
* a **regex pass** over the (confusable-folded) source text that also catches
  shellcode markers and payloads in code the AST cannot parse.

Pure stdlib plus :mod:`core.text_normalization`.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Any

from .text_normalization import collapse_confusables

# Names whose invocation is dangerous on its own.
_DANGEROUS_CALLS = {
    "eval",
    "exec",
    "compile",
    "__import__",
    "execfile",
}

# module.function attribute chains that are dangerous.
_DANGEROUS_ATTRS = {
    ("os", "system"),
    ("os", "popen"),
    ("os", "exec"),
    ("os", "execv"),
    ("os", "execve"),
    ("os", "execvp"),
    ("os", "spawn"),
    ("os", "fork"),
    ("subprocess", "run"),
    ("subprocess", "call"),
    ("subprocess", "Popen"),
    ("subprocess", "check_output"),
    ("subprocess", "check_call"),
    ("pty", "spawn"),
    ("ctypes", "CDLL"),
    ("ctypes", "windll"),
    ("importlib", "import_module"),
}

# Dynamic-obfuscation helpers (used to reach attributes/imports by string).
_OBFUSCATION_CALLS = {"getattr", "setattr", "globals", "vars", "__import__"}

_REGEX_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("subprocess", re.compile(r"\bsubprocess\b")),
    ("os_system", re.compile(r"\bos\.system\b")),
    ("shell_pipe", re.compile(r"\b(?:bash|sh|zsh)\s+-c\b")),
    ("reverse_shell", re.compile(r"/dev/tcp/|nc\s+-e|socket\.socket\([^)]*SOCK_STREAM")),
    ("shellcode", re.compile(r"(?:\\x[0-9a-fA-F]{2}){6,}")),
    ("sandbox_escape", re.compile(r"__globals__|__builtins__|__subclasses__|func_globals")),
    ("dynamic_import", re.compile(r"__import__\s*\(")),
    ("ctypes", re.compile(r"\bctypes\b|\bcdll\b|\bwindll\b")),
    ("eval_exec", re.compile(r"\b(?:eval|exec)\s*\(")),
]


@dataclass
class SandboxFinding:
    rule: str
    detail: str
    line: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"rule": self.rule, "detail": self.detail, "line": self.line}


@dataclass
class SandboxResult:
    findings: list[SandboxFinding] = field(default_factory=list)
    parsed: bool = True  # whether the AST pass succeeded

    @property
    def dangerous(self) -> bool:
        return bool(self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "dangerous": self.dangerous,
            "parsed": self.parsed,
            "findings": [f.to_dict() for f in self.findings],
        }


class _Visitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.findings: list[SandboxFinding] = []

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        func = node.func
        if isinstance(func, ast.Name):
            if func.id in _DANGEROUS_CALLS:
                self.findings.append(
                    SandboxFinding("dangerous_call", f"call to {func.id}()", node.lineno)
                )
            elif func.id in _OBFUSCATION_CALLS:
                self.findings.append(
                    SandboxFinding(
                        "dynamic_obfuscation",
                        f"dynamic access via {func.id}()",
                        node.lineno,
                    )
                )
        elif isinstance(func, ast.Attribute):
            base = func.value
            if isinstance(base, ast.Name):
                pair = (base.id, func.attr)
                if pair in _DANGEROUS_ATTRS:
                    self.findings.append(
                        SandboxFinding(
                            "dangerous_attr",
                            f"call to {base.id}.{func.attr}()",
                            node.lineno,
                        )
                    )
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            root = alias.name.split(".")[0]
            if root in {"subprocess", "ctypes", "pty"}:
                self.findings.append(
                    SandboxFinding("dangerous_import", f"import {alias.name}", node.lineno)
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        root = (node.module or "").split(".")[0]
        if root in {"subprocess", "ctypes", "pty"}:
            self.findings.append(
                SandboxFinding("dangerous_import", f"from {node.module} import ...", node.lineno)
            )
        self.generic_visit(node)


def scan_code(source: str) -> SandboxResult:
    """Scan a code payload for dangerous constructs.

    Runs the AST pass when the source is valid Python, then always runs the
    regex pass over the confusable-folded text so obfuscated or non-parseable
    payloads are still caught.  Findings are de-duplicated by (rule, line).
    """

    result = SandboxResult()
    if not source:
        return result

    folded = collapse_confusables(source)

    # AST pass
    try:
        tree = ast.parse(folded)
    except SyntaxError:
        result.parsed = False
    else:
        visitor = _Visitor()
        visitor.visit(tree)
        result.findings.extend(visitor.findings)

    # Regex pass (line-aware)
    for rule, pattern in _REGEX_RULES:
        for m in pattern.finditer(folded):
            line = folded.count("\n", 0, m.start()) + 1
            result.findings.append(
                SandboxFinding(rule, f"matched /{pattern.pattern}/", line)
            )

    # de-duplicate
    seen: set[tuple[str, int, str]] = set()
    unique: list[SandboxFinding] = []
    for f in result.findings:
        key = (f.rule, f.line, f.detail)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    result.findings = unique
    return result
