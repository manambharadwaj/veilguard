#!/usr/bin/env python3
"""Compare VeilGuard detection against other secret scanners.

Runs detect-secrets, gitleaks, and trufflehog on the benchmark corpus
and produces a side-by-side comparison table.

Prerequisites (install before running):
    pip install detect-secrets
    brew install gitleaks    # or download from GitHub releases
    brew install trufflehog  # or download from GitHub releases

Usage:
    python benchmarks/compare.py
    python benchmarks/compare.py --json
    python benchmarks/compare.py --latex
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

CORPUS_DIR = Path(__file__).parent / "corpus"
MANIFEST_PATH = CORPUS_DIR / "manifest.json"


def load_manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def get_expected_positive_files(manifest: dict) -> set[str]:
    """Return set of rel paths that should contain at least one finding."""
    return {
        rel for rel, meta in manifest.items()
        if meta["category"] == "true_positive"
    }


def get_expected_negative_files(manifest: dict) -> set[str]:
    return {
        rel for rel, meta in manifest.items()
        if meta["category"] == "true_negative"
    }


# ---------------------------------------------------------------------------
# VeilGuard
# ---------------------------------------------------------------------------

def run_veilguard(manifest: dict) -> dict:
    from veilguard.patterns import CREDENTIAL_PATTERNS
    from veilguard.scan import _is_known_example

    start = time.perf_counter()
    detected_files: set[str] = set()
    for rel_path in manifest:
        abs_path = CORPUS_DIR / rel_path
        if not abs_path.is_file():
            continue
        try:
            content = abs_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in content.splitlines():
            if len(line) > 4096:
                continue
            for pattern in CREDENTIAL_PATTERNS:
                m = pattern.regex.search(line)
                if m and not _is_known_example(line, m):
                    detected_files.add(rel_path)
                    break
            else:
                continue
            break
    elapsed = time.perf_counter() - start
    return {"tool": "veilguard", "detected_files": detected_files, "elapsed": elapsed}


# ---------------------------------------------------------------------------
# detect-secrets
# ---------------------------------------------------------------------------

def run_detect_secrets(manifest: dict) -> dict | None:
    if not shutil.which("detect-secrets"):
        print("  [skip] detect-secrets not installed", file=sys.stderr)
        return None

    start = time.perf_counter()
    detected_files: set[str] = set()

    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        baseline_path = f.name

    try:
        result = subprocess.run(
            ["detect-secrets", "scan", str(CORPUS_DIR)],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0 and result.stdout:
            data = json.loads(result.stdout)
            for file_path in data.get("results", {}):
                rel = str(Path(file_path).relative_to(CORPUS_DIR))
                if data["results"][file_path]:
                    detected_files.add(rel)
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError) as e:
        print(f"  [error] detect-secrets: {e}", file=sys.stderr)
        return None
    finally:
        Path(baseline_path).unlink(missing_ok=True)

    elapsed = time.perf_counter() - start
    return {"tool": "detect-secrets", "detected_files": detected_files, "elapsed": elapsed}


# ---------------------------------------------------------------------------
# gitleaks
# ---------------------------------------------------------------------------

def run_gitleaks(manifest: dict) -> dict | None:
    if not shutil.which("gitleaks"):
        print("  [skip] gitleaks not installed", file=sys.stderr)
        return None

    start = time.perf_counter()
    detected_files: set[str] = set()

    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        report_path = f.name

    try:
        subprocess.run(
            [
                "gitleaks", "detect",
                "--source", str(CORPUS_DIR),
                "--no-git",
                "--report-format", "json",
                "--report-path", report_path,
            ],
            capture_output=True, text=True, timeout=120,
        )
        report = Path(report_path)
        if report.is_file() and report.stat().st_size > 0:
            findings = json.loads(report.read_text(encoding="utf-8"))
            for finding in findings:
                file_path = finding.get("File", "")
                try:
                    rel = str(Path(file_path).relative_to(CORPUS_DIR))
                    detected_files.add(rel)
                except ValueError:
                    detected_files.add(file_path)
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError) as e:
        print(f"  [error] gitleaks: {e}", file=sys.stderr)
        return None
    finally:
        Path(report_path).unlink(missing_ok=True)

    elapsed = time.perf_counter() - start
    return {"tool": "gitleaks", "detected_files": detected_files, "elapsed": elapsed}


# ---------------------------------------------------------------------------
# trufflehog
# ---------------------------------------------------------------------------

def run_trufflehog(manifest: dict) -> dict | None:
    if not shutil.which("trufflehog"):
        print("  [skip] trufflehog not installed", file=sys.stderr)
        return None

    start = time.perf_counter()
    detected_files: set[str] = set()

    try:
        result = subprocess.run(
            [
                "trufflehog", "filesystem",
                str(CORPUS_DIR),
                "--json",
                "--no-verification",
            ],
            capture_output=True, text=True, timeout=120,
        )
        for line in result.stdout.strip().splitlines():
            if not line.strip():
                continue
            try:
                finding = json.loads(line)
                file_path = finding.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", "")
                if file_path:
                    try:
                        rel = str(Path(file_path).relative_to(CORPUS_DIR))
                        detected_files.add(rel)
                    except ValueError:
                        detected_files.add(file_path)
            except json.JSONDecodeError:
                continue
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"  [error] trufflehog: {e}", file=sys.stderr)
        return None

    elapsed = time.perf_counter() - start
    return {"tool": "trufflehog", "detected_files": detected_files, "elapsed": elapsed}


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------

def compute_metrics(detected: set[str], positive_files: set[str], negative_files: set[str]) -> dict:
    tp = len(detected & positive_files)
    fp = len(detected & negative_files)
    fn = len(positive_files - detected)
    tn = len(negative_files - detected)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def print_comparison(results: list[dict], positive_files: set[str], negative_files: set[str]) -> None:
    print("=" * 70)
    print("Tool Comparison on VeilGuard Benchmark Corpus")
    print(f"  True-positive files: {len(positive_files)}")
    print(f"  True-negative files: {len(negative_files)}")
    print("=" * 70)

    header = f"  {'Tool':<18} {'TP':>4} {'FP':>4} {'FN':>4} {'Prec':>7} {'Recall':>7} {'F1':>7} {'Time':>7}"
    print(header)
    print(f"  {'-'*18} {'-'*4} {'-'*4} {'-'*4} {'-'*7} {'-'*7} {'-'*7} {'-'*7}")

    for r in results:
        m = compute_metrics(r["detected_files"], positive_files, negative_files)
        print(
            f"  {r['tool']:<18} {m['tp']:>4} {m['fp']:>4} {m['fn']:>4} "
            f"{m['precision']:>7.4f} {m['recall']:>7.4f} {m['f1']:>7.4f} "
            f"{r['elapsed']:>6.2f}s"
        )


def format_latex(results: list[dict], positive_files: set[str], negative_files: set[str]) -> str:
    lines = [
        r"\begin{table}[ht]",
        r"\centering",
        r"\caption{Comparison of Secret Scanning Tools on Benchmark Corpus}",
        r"\label{tab:tool-comparison}",
        r"\begin{tabular}{lrrrrrrr}",
        r"\toprule",
        r"Tool & TP & FP & FN & Precision & Recall & F1 & Time (s) \\",
        r"\midrule",
    ]
    for r in results:
        m = compute_metrics(r["detected_files"], positive_files, negative_files)
        lines.append(
            f"\\texttt{{{r['tool']}}} & {m['tp']} & {m['fp']} & {m['fn']} "
            f"& {m['precision']:.2f} & {m['recall']:.2f} & {m['f1']:.2f} "
            f"& {r['elapsed']:.2f} \\\\"
        )
    lines.extend([
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
    ])
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare secret scanners")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--latex", action="store_true")
    args = parser.parse_args()

    manifest = load_manifest()
    positive_files = get_expected_positive_files(manifest)
    negative_files = get_expected_negative_files(manifest)

    runners = [
        ("veilguard", run_veilguard),
        ("detect-secrets", run_detect_secrets),
        ("gitleaks", run_gitleaks),
        ("trufflehog", run_trufflehog),
    ]

    results = []
    for name, runner in runners:
        print(f"Running {name}...", file=sys.stderr)
        r = runner(manifest)
        if r is not None:
            results.append(r)

    if args.json:
        output = []
        for r in results:
            m = compute_metrics(r["detected_files"], positive_files, negative_files)
            output.append({"tool": r["tool"], **m, "elapsed": r["elapsed"]})
        print(json.dumps(output, indent=2))
        return

    print_comparison(results, positive_files, negative_files)

    if args.latex:
        print("\n" + format_latex(results, positive_files, negative_files))


if __name__ == "__main__":
    main()
