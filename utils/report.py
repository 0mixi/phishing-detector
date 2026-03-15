"""Report utilities for Phishing Detector."""
import json
from datetime import datetime

def print_report(results: list):
    total    = len(results)
    phishing = sum(1 for r in results if r["is_phishing"])
    safe     = total - phishing
    print("=" * 55)
    print(f"  SCAN SUMMARY")
    print(f"  Total URLs : {total}")
    print(f"  Phishing   : {phishing}")
    print(f"  Safe       : {safe}")
    print("=" * 55)
    if phishing:
        print("\n  ⚠️  PHISHING URLs DETECTED:")
        for r in results:
            if r["is_phishing"]:
                print(f"\n  URL      : {r['url']}")
                print(f"  Score    : {r['raw_score']}  |  Confidence: {r['confidence']*100:.1f}%")
                for factor in r["risk_factors"]:
                    print(f"    • {factor}")

def save_report(results: list, output_path: str):
    report = {
        "generated": datetime.now().isoformat(),
        "summary": {
            "total":    len(results),
            "phishing": sum(1 for r in results if r["is_phishing"]),
            "safe":     sum(1 for r in results if not r["is_phishing"]),
        },
        "results": results
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
