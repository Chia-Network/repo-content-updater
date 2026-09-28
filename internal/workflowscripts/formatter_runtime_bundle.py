"""Consumer-shipped formatter runtime bundle constants (loader markers + sibling stems)."""

from __future__ import annotations

LOADER_RESOLVE_MARKER_FILENAMES: tuple[str, ...] = (
    "isolated_module_exec.py",
    "script_dir_isolated_load.py",
    "trusted_formatter_loader_bootstrap.py",
    "trusted_formatter_loader.py",
)

FORMATTER_SIBLING_MODULE_STEMS: tuple[str, ...] = (
    "malware_verdict_patterns_regex",
    "malware_verdict_patterns_structure",
    "malware_verdict_patterns",
    "malware_verdict_policy_types",
    "malware_verdict_policy_lexical",
    "malware_verdict_policy_context",
    "malware_verdict_policy_strip_eligibility",
    "malware_verdict_policy_rules_select",
    "malware_verdict_policy_rules_strip",
    "malware_verdict_policy_analysis",
    "malware_verdict_policy",
)

FORMATTER_RUNTIME_FILENAMES: tuple[str, ...] = (
    "scripts_dir_module_loader.py",
    "module_exec_scrub_bootstrap.py",
    "module_exec_scrub.py",
    *LOADER_RESOLVE_MARKER_FILENAMES,
    "trusted_formatter_loader_cold_start.py",
    "formatter_runtime_bundle.py",
    "malware_verdict_formatter.py",
    *(f"{stem}.py" for stem in FORMATTER_SIBLING_MODULE_STEMS),
)
