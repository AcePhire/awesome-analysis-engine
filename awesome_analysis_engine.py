import sys
import timeit

from mongodb_handler import add_fuzzy_hash, add_tool_analysis, create_apk_analysis
from tools import *


# Analyze APK using multiple tools
def analyze(path):
    create_apk_analysis(path)

    file_hash = hash_file(path)

    mobsf_data = mobsf_analysis(path)
    add_tool_analysis(file_hash, "MOBSF_ANALYSIS", mobsf_data)

    apkid_data = apkid_analysis(path)
    add_tool_analysis(file_hash, "APKID_ANALYSIS", apkid_data)

    ssdeep_hashes = ssdeep_analysis(path)
    for ssdeep_hash in ssdeep_hashes:
        add_fuzzy_hash(file_hash, {ssdeep_hash[0]: ssdeep_hash[1]})

    quark_engine_data = quark_engine_analysis(path)
    add_tool_analysis(file_hash, "QUARK_ENGINE_ANALYSIS", quark_engine_data)

    androcfg_data = androcfg_analysis(path)
    add_tool_analysis(file_hash, "ANDROCFG_ANALYSIS", androcfg_data)

    virustotal_data = virustotal_analysis(path)
    add_tool_analysis(file_hash, "VIRUSTOTAL_ANALYSIS", virustotal_data)

    malwarebazaar_data = malwarebazaar_analysis(path)
    add_tool_analysis(file_hash, "MALWAREBAZAAR_ANALYSIS", malwarebazaar_data)

    apk_info_data = apk_info_analysis(path)
    add_tool_analysis(file_hash, "APK_INFO_ANALYSIS", apk_info_data)

    yara_data = yara_analysis(path)
    add_tool_analysis(file_hash, "YARA_ANALYSIS", yara_data)


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("No path given!")
        exit()

    path = sys.argv[1]
    analyze(path)
    # report_id = hash_file(path)
    # saveReport(report, f"{report_id}.json")
