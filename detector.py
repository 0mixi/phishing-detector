#!/usr/bin/env python3
"""
Phishing Link Detector
Author: Om Awachar
ML-based tool to detect and classify malicious phishing URLs using
domain patterns, URL length, special character ratios, and keyword analysis.
"""

import argparse
import json
import sys
from utils.extractor import extract_features
from utils.predictor import predict
from utils.report import print_report, save_report

BANNER = """
██████╗ ██╗  ██╗██╗███████╗██╗  ██╗
██╔══██╗██║  ██║██║██╔════╝██║  ██║
██████╔╝███████║██║███████╗███████║
██╔═══╝ ██╔══██║██║╚════██║██╔══██║
██║     ██║  ██║██║███████║██║  ██║
╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝
Phishing Link Detector v1.0 — by Om Awachar
"""

def scan_urls(urls: list, output: str = None, verbose: bool = False) -> list:
    print(BANNER)
    results = []
    print(f"[*] Scanning {len(urls)} URL(s)...\n")
    for url in urls:
        features = extract_features(url)
        result   = predict(url, features)
        results.append(result)
        label   = "🔴 PHISHING" if result["is_phishing"] else "🟢 SAFE"
        conf    = f"{result['confidence']*100:.1f}%"
        print(f"  {label}  ({conf})  {url}")
        if verbose:
            for k, v in result["features"].items():
                print(f"       {k}: {v}")
    print()
    print_report(results)
    if output:
        save_report(results, output)
        print(f"\n[✓] Report saved to {output}")
    return results

def main():
    parser = argparse.ArgumentParser(description="Phishing Link Detector")
    parser.add_argument("--url",     help="Single URL to check")
    parser.add_argument("--file",    help="File with one URL per line")
    parser.add_argument("--output",  help="Save JSON report to this path")
    parser.add_argument("--verbose", action="store_true", help="Show all features")
    args = parser.parse_args()

    urls = []
    if args.url:
        urls = [args.url]
    elif args.file:
        with open(args.file) as f:
            urls = [line.strip() for line in f if line.strip()]
    else:
        parser.print_help()
        sys.exit(1)

    scan_urls(urls, args.output, args.verbose)

if __name__ == "__main__":
    main()
