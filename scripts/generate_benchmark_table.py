#!/usr/bin/env python3
"""
Script to generate a benchmark comparison table from cargo criterion JSONL files.

Workflow:
1. Generate JSONL files: just benchmarks-generate
2. Parse and create table: just benchmarks-table
3. Or do both: just benchmarks

Usage:
  python3 scripts/generate_benchmark_table.py          # Generate table from existing JSONL files
  python3 scripts/generate_benchmark_table.py --help   # Show help
"""

import json
import sys
from pathlib import Path

def parse_benchmark_jsonl_file(filepath):
    """Parse a JSONL file from cargo criterion and extract benchmark times."""
    benchmarks = {}

    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    if data.get('reason') == 'benchmark-complete':
                        benchmark_id = data['id']
                        # Extract factor name and benchmark type from id like "password/single_setup"
                        if '/' in benchmark_id:
                            factor_name, bench_type = benchmark_id.split('/', 1)
                        else:
                            # Fallback for older format
                            factor_name = "unknown"
                            bench_type = benchmark_id

                        # Convert nanoseconds to milliseconds for readability
                        time_ns = data['typical']['estimate']
                        time_ms = time_ns / 1_000_000

                        if factor_name not in benchmarks:
                            benchmarks[factor_name] = {}
                        benchmarks[factor_name][bench_type] = f"{time_ms:.2f}ms"
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        print(f"File {filepath} not found", file=sys.stderr)

    return benchmarks

def parse_benchmark_json(json_text):
    """Parse the JSON output from cargo criterion and extract benchmark times."""
    benchmarks = {}
    lines = json_text.strip().split('\n')

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            if data.get('reason') == 'benchmark-complete':
                benchmark_id = data['id']
                # Convert nanoseconds to milliseconds for readability
                time_ns = data['typical']['estimate']
                time_ms = time_ns / 1_000_000
                benchmarks[benchmark_id] = f"{time_ms:.2f}ms"
        except json.JSONDecodeError:
            continue

    return benchmarks

def format_time(time_str):
    """Format time for display, keeping it short."""
    if time_str.endswith('ms'):
        value = float(time_str[:-2])
        if value >= 100:
            return f"{value:.0f}ms"
        elif value >= 10:
            return f"{value:.1f}ms"
        else:
            return f"{value:.2f}ms"
    return time_str

def collect_all_results():
    """Collect benchmark results from target/criterion directory."""
    criterion_dir = Path(__file__).parent.parent / "target" / "criterion"

    if not criterion_dir.exists():
        return {}

    results = {}

    # Map factor names to their expected benchmark names
    factor_benchmarks = {
        'password': ['single_setup', 'single_derive', 'multiple_setup_3_threshold_3', 'multiple_derive_3', 'threshold_derive_2_of_3'],
        'hmacsha1': ['single_setup', 'single_derive', 'multiple_setup_3_threshold_3', 'multiple_derive_3', 'threshold_derive_2_of_3'],
        'hotp': ['single_setup', 'single_derive', 'multiple_setup_3_threshold_3', 'multiple_derive_3', 'threshold_derive_2_of_3'],
        'ooba': ['single_setup', 'single_derive', 'multiple_setup_3_threshold_3', 'multiple_derive_3', 'threshold_derive_2_of_3'],
        'passkey': ['single_setup', 'single_derive', 'multiple_setup_3_threshold_3', 'multiple_derive_3', 'threshold_derive_2_of_3'],
        'question': ['single_setup', 'single_derive', 'multiple_setup_3_threshold_3', 'multiple_derive_3', 'threshold_derive_2_of_3'],
        'totp': ['single_setup', 'single_derive', 'multiple_setup_3_threshold_3', 'multiple_derive_3', 'threshold_derive_2_of_3'],
        'uuid': ['single_setup', 'single_derive', 'multiple_setup_3_threshold_3', 'multiple_derive_3', 'threshold_derive_2_of_3'],
        'stack': ['single_setup', 'single_derive', 'multiple_setup_3_threshold_3', 'multiple_derive_3', 'threshold_derive_2_of_3'],
    }

    for factor, expected_benchmarks in factor_benchmarks.items():
        results[factor] = {}
        for bench in expected_benchmarks:
            # Try to find this benchmark result
            bench_dir = criterion_dir / bench
            if bench_dir.exists():
                estimates_file = bench_dir / "new" / "estimates.json"
                if estimates_file.exists():
                    try:
                        with open(estimates_file, 'r') as f:
                            data = json.load(f)
                            time_ns = data['typical']['estimate']
                            time_ms = time_ns / 1_000_000
                            results[factor][bench] = f"{time_ms:.2f}ms"
                    except (json.JSONDecodeError, KeyError):
                        pass

    return results

# Global storage for results
all_results = {}

def run_benchmarks_for_factors(factors):
    """Parse benchmark results from existing JSONL files."""
    results = {}

    for factor in factors:
        print(f"Loading benchmarks for {factor}...")
        jsonl_file = Path(__file__).parent.parent / f"{factor}.jsonl"

        if jsonl_file.exists():
            # Parse existing JSONL file
            factor_results = parse_benchmark_jsonl_file(jsonl_file)
            if factor in factor_results:
                results[factor] = factor_results[factor]
                print(f"  ✓ Parsed existing results for {factor}")
            else:
                print(f"  ✗ No valid results found for {factor}")
        else:
            print(f"  ✗ JSONL file {jsonl_file} not found")

    return results

def main():
    if len(sys.argv) > 1 and sys.argv[1] in ['--help', '-h']:
        print(__doc__)
        return

    # Define the factor types we want to benchmark
    # TOTP is included but may be missing due to slow RSA operations
    factor_types = ['password', 'hmacsha1', 'hotp', 'ooba', 'passkey', 'question', 'totp', 'uuid', 'stack']

    # Load benchmark results from JSONL files
    results = run_benchmarks_for_factors(factor_types)

    if not results:
        print("No benchmark results found.", file=sys.stderr)
        print("Generate them with: just benchmarks-generate", file=sys.stderr)
        print("Or for all factors: just benchmarks-generate-all", file=sys.stderr)
        return

    # Column mapping - map the benchmark names to table columns
    column_mapping = {
        'single_setup': 'single_setup',
        'single_derive': 'single_derive',
        'multiple_setup_3_threshold_3': 'multiple_setup',
        'multiple_derive_3': 'multiple_derive (3 of 3)',
        'threshold_derive_2_of_3': 'multiple_derive (2 of 3)'
    }

    # Generate table
    columns = list(column_mapping.values())
    print("\n| factor | " + " | ".join(columns) + " |")
    print("|" + "|".join(["---"] * (len(columns) + 1)) + "|")

    for factor in sorted(results.keys()):
        benchmarks = results[factor]
        row = [factor]
        for col_key in column_mapping.keys():
            time = benchmarks.get(col_key, "-")
            if time != "-":
                time = format_time(time)
            row.append(time)
        print("| " + " | ".join(row) + " |")

if __name__ == "__main__":
    main()
