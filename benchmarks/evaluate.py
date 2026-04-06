#!/usr/bin/env python3
"""Evaluate VeilGuard scanner against the benchmark corpus.

Computes per-category and overall precision, recall, and F1 score.
Measures scan throughput at varying corpus sizes.

Usage:
    python benchmarks/evaluate.py              # full evaluation
    python benchmarks/evaluate.py --latex      # also emit LaTeX table
    python benchmarks/evaluate.py --json       # output raw JSON results
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from veilguard.patterns import (  # noqa: E402
    CREDENTIAL_PATTERNS,
    CREDENTIAL_PREFIX_QUICK_CHECK,
    KNOWN_EXAMPLE_KEYS,
    PLACEHOLDER_INDICATORS,
)
from veilguard.scan import _is_known_example, scan  # noqa: E402

CORPUS_DIR = Path(__file__).parent / "corpus"
MANIFEST_PATH = CORPUS_DIR / "manifest.json"


def load_manifest() -> dict:
    if not MANIFEST_PATH.is_file():
        print("Manifest not found. Run: python benchmarks/generate_corpus.py", file=sys.stderr)
        sys.exit(1)
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def scan_file_for_patterns(file_path: Path) -> list[dict]:
    """Scan a single file using VeilGuard's pattern engine directly."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    findings = []
    for i, line in enumerate(content.splitlines(), start=1):
        if len(line) > 4096:
            continue
        for pattern in CREDENTIAL_PATTERNS:
            m = pattern.regex.search(line)
            if m and not _is_known_example(line, m):
                findings.append({"pattern_id": pattern.id, "line": i})
                break
    return findings


def evaluate_detection(manifest: dict) -> dict:
    """Run VeilGuard pattern matching on corpus and compare to ground truth."""
    true_positives = 0
    false_negatives = 0
    false_positives = 0
    true_negatives = 0

    per_category: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0})
    file_results: list[dict] = []

    for rel_path, meta in manifest.items():
        abs_path = CORPUS_DIR / rel_path
        if not abs_path.is_file():
            continue

        file_findings = scan_file_for_patterns(abs_path)

        if meta["category"] == "true_positive":
            expected = meta.get("expected_findings", [])
            expected_ids = {e["pattern_id"] for e in expected}
            found_ids = {f["pattern_id"] for f in file_findings}

            for eid in expected_ids:
                if eid in found_ids:
                    true_positives += 1
                    per_category[eid]["tp"] += 1
                else:
                    false_negatives += 1
                    per_category[eid]["fn"] += 1

            for fid in found_ids - expected_ids:
                false_positives += 1
                per_category[fid]["fp"] += 1

            file_results.append({
                "file": rel_path,
                "expected": sorted(expected_ids),
                "found": sorted(found_ids),
                "match": expected_ids == found_ids,
            })

        elif meta["category"] == "true_negative":
            if file_findings:
                false_positives += len(file_findings)
                for f in file_findings:
                    per_category[f["pattern_id"]]["fp"] += 1
                file_results.append({
                    "file": rel_path,
                    "expected": [],
                    "found": [f["pattern_id"] for f in file_findings],
                    "match": False,
                })
            else:
                true_negatives += 1
                file_results.append({
                    "file": rel_path,
                    "expected": [],
                    "found": [],
                    "match": True,
                })

        elif meta["category"] == "edge_case":
            expected_count = meta.get("expected_count", 0)
            actual_count = len(file_findings)
            file_results.append({
                "file": rel_path,
                "expected_count": expected_count,
                "actual_count": actual_count,
                "match": expected_count == actual_count,
                "description": meta.get("description", ""),
            })

    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0.0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    category_metrics = {}
    for cat_id, counts in sorted(per_category.items()):
        tp_c = counts["tp"]
        fp_c = counts["fp"]
        fn_c = counts["fn"]
        p = tp_c / (tp_c + fp_c) if (tp_c + fp_c) > 0 else 0.0
        r = tp_c / (tp_c + fn_c) if (tp_c + fn_c) > 0 else 0.0
        f = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
        category_metrics[cat_id] = {"precision": p, "recall": r, "f1": f, "tp": tp_c, "fp": fp_c, "fn": fn_c}

    return {
        "overall": {
            "true_positives": true_positives,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "true_negatives": true_negatives,
            "precision": precision,
            "recall": recall,
            "f1": f1,
        },
        "per_category": category_metrics,
        "file_results": file_results,
    }


def measure_throughput() -> dict:
    """Measure scan speed on a real project-level scan."""
    tp_dir = CORPUS_DIR / "true_positives"
    all_files = [f for f in CORPUS_DIR.rglob("*") if f.is_file() and f.name != "manifest.json"]
    file_count = len(all_files)
    total_lines = sum(
        len(f.read_text(encoding="utf-8", errors="replace").splitlines())
        for f in all_files
    )

    iterations = 5
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        for f in all_files:
            scan_file_for_patterns(f)
        elapsed = time.perf_counter() - start
        times.append(elapsed)

    avg_time = sum(times) / len(times)
    return {
        "files": file_count,
        "total_lines": total_lines,
        "avg_seconds": round(avg_time, 4),
        "files_per_second": round(file_count / avg_time, 1) if avg_time > 0 else 0,
        "lines_per_second": round(total_lines / avg_time, 1) if avg_time > 0 else 0,
        "iterations": iterations,
    }


def format_latex_table(results: dict) -> str:
    """Format results as a LaTeX table for paper inclusion."""
    lines = [
        r"\begin{table}[ht]",
        r"\centering",
        r"\caption{VeilGuard Detection Accuracy by Pattern Category}",
        r"\label{tab:detection-accuracy}",
        r"\begin{tabular}{lrrrrr}",
        r"\toprule",
        r"Pattern ID & TP & FP & FN & Precision & Recall \\",
        r"\midrule",
    ]
    for cat_id, m in sorted(results["per_category"].items()):
        lines.append(
            f"\\texttt{{{cat_id}}} & {m['tp']} & {m['fp']} & {m['fn']} "
            f"& {m['precision']:.2f} & {m['recall']:.2f} \\\\"
        )
    o = results["overall"]
    lines.extend([
        r"\midrule",
        f"\\textbf{{Overall}} & {o['true_positives']} & {o['false_positives']} "
        f"& {o['false_negatives']} & {o['precision']:.2f} & {o['recall']:.2f} \\\\",
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
    ])
    return "\n".join(lines)


def print_summary(results: dict, throughput: dict) -> None:
    o = results["overall"]
    print("=" * 60)
    print("VeilGuard Benchmark Evaluation")
    print("=" * 60)
    print(f"\nOverall Metrics:")
    print(f"  True Positives:  {o['true_positives']}")
    print(f"  False Positives: {o['false_positives']}")
    print(f"  False Negatives: {o['false_negatives']}")
    print(f"  True Negatives:  {o['true_negatives']}")
    print(f"  Precision:       {o['precision']:.4f}")
    print(f"  Recall:          {o['recall']:.4f}")
    print(f"  F1 Score:        {o['f1']:.4f}")

    print(f"\nPer-Category Breakdown:")
    print(f"  {'Pattern ID':<25} {'TP':>3} {'FP':>3} {'FN':>3} {'Prec':>6} {'Recall':>6} {'F1':>6}")
    print(f"  {'-'*25} {'-'*3} {'-'*3} {'-'*3} {'-'*6} {'-'*6} {'-'*6}")
    for cat_id, m in sorted(results["per_category"].items()):
        print(
            f"  {cat_id:<25} {m['tp']:>3} {m['fp']:>3} {m['fn']:>3} "
            f"{m['precision']:>6.2f} {m['recall']:>6.2f} {m['f1']:>6.2f}"
        )

    mismatched = [f for f in results["file_results"] if not f["match"]]
    if mismatched:
        print(f"\nMismatched Files ({len(mismatched)}):")
        for f in mismatched:
            print(f"  {f['file']}: expected={f.get('expected', f.get('expected_count'))}, "
                  f"found={f.get('found', f.get('actual_count'))}")

    print(f"\nThroughput:")
    print(f"  Files scanned:     {throughput['files']}")
    print(f"  Total lines:       {throughput['total_lines']}")
    print(f"  Avg scan time:     {throughput['avg_seconds']}s ({throughput['iterations']} iterations)")
    print(f"  Files/second:      {throughput['files_per_second']}")
    print(f"  Lines/second:      {throughput['lines_per_second']}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate VeilGuard scanner")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    parser.add_argument("--latex", action="store_true", help="Also emit LaTeX table")
    args = parser.parse_args()

    manifest = load_manifest()
    results = evaluate_detection(manifest)
    throughput = measure_throughput()

    if args.json:
        output = {"detection": results, "throughput": throughput}
        print(json.dumps(output, indent=2))
        return

    print_summary(results, throughput)

    if args.latex:
        print("\n" + "=" * 60)
        print("LaTeX Table:")
        print("=" * 60)
        print(format_latex_table(results))


if __name__ == "__main__":
    main()
