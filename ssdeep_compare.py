import json
import sys

import ssdeep

from mongodb_handler import _get_fuzzy_hashes_collection


def hash_compare(sha256):
    source_hashes = list(
        _get_fuzzy_hashes_collection().find({"tool": "ssdeep", "sha256": sha256})
    )
    target_hashes = list(_get_fuzzy_hashes_collection().find({"tool": "ssdeep"}))

    results = []
    for source_hash in source_hashes:
        current_hash = {
            "sha256": source_hash["sha256"],
            "filename": source_hash["filename"],
            "fuzzy_hash": source_hash["fuzzy_hash"],
        }

        comparison_scores = []

        for target_hash in target_hashes:
            if source_hash["fuzzy_hash"] != target_hash["fuzzy_hash"]:
                score = ssdeep.compare(
                    source_hash["fuzzy_hash"], target_hash["fuzzy_hash"]
                )

                if score == 0:
                    continue

                comparison_scores.append(
                    {
                        "sha256": target_hash["sha256"],
                        "filename": target_hash["filename"],
                        "fuzzy_hash": target_hash["fuzzy_hash"],
                        "score": score,
                    }
                )

        if len(comparison_scores) == 0:
            continue
        results.append(
            {
                "source_hash": current_hash,
                "comparison_scores": comparison_scores,
            }
        )

    return results


if __name__ == "__main__":
    sha256 = sys.argv[1]
    results = hash_compare(sha256)
    print(json.dumps(results, indent=2))
