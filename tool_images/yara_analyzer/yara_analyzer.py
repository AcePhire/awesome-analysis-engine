import sys
import yara
import zipfile
import json
from androguard.misc import AnalyzeAPK
from androguard import util as AndroUtil

def scan_apk(apk_path: str, rules: yara.Rules) -> dict:
    results = {"apk": apk_path, "matches": [], "metadata": {}}

    a, d, dx = AnalyzeAPK(apk_path)

    results["metadata"] = {
        "package":      a.get_package(),
        "version":      a.get_androidversion_name(),
        "min_sdk":      a.get_min_sdk_version(),
        "permissions":  a.get_permissions(),
        "activities":   a.get_activities(),
    }

    with open(apk_path, "rb") as f:
        raw_data = f.read()
    hits = rules.match(data=raw_data)
    if hits:
        results["matches"].append({"source": "raw_apk", "rules": [str(h) for h in hits]})

    dex_list = d if isinstance(d, list) else [d]

    for i, dex in enumerate(dex_list):
        dex.raw.seek(0)
        dex_bytes = dex.raw.read()

        hits = rules.match(data=dex_bytes)
        if hits:
            results["matches"].append({
                "source": f"classes{'' if i == 0 else i}.dex",
                "rules": [str(h) for h in hits]
            })

    with zipfile.ZipFile(apk_path) as z:
        for name in z.namelist():
            data = z.read(name)
            hits = rules.match(data=data)
            if hits:
                results["matches"].append({"source": name, "rules": [str(h) for h in hits]})

    return results

if __name__ == "__main__":
    AndroUtil.set_log("CRITICAL")
    apk_path = sys.argv[1]
    rules_path = sys.argv[2]

    rules = yara.compile(filepath=rules_path)
    results = scan_apk(apk_path, rules)
    print(json.dumps(results, indent=2))
