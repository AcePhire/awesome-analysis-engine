import docker
import json
import ssdeep
from pathlib import Path

client = docker.from_env()

def get_fuzzy_hashes():
    reports = Path("reports")
    fuzzy_hashes = []

    for report in reports.iterdir():
        with open(report, "r") as report_file:
            report_json = json.load(report_file)
            for analysis in report_json:
                if analysis["tool"] == "ssdeep":
                    fuzzy_hashes.append(analysis["tool_results"][0]["blocksize:hash:hash"])

    return fuzzy_hashes

def compare():
    fuzzy_hashes = get_fuzzy_hashes()
    results = []
    
    for base_hash in fuzzy_hashes:
        comparison_scores = []

        for compared_hash in fuzzy_hashes:
            if base_hash != compared_hash:
                score = ssdeep.compare(base_hash, compared_hash)

                comparison_scores.append({
                    "compared_hash": compared_hash,
                    "score": score
                })

        results.append({
            "base_hash": base_hash,
            "comparison_scores": comparison_scores
        })

    return results

if __name__ ==  "__main__":
    results = compare()
    print(json.dumps(results, indent=2))
