import sys
import timeit

from postgres_handler import (
    add_apk_analysis,
    initalizeDatabase,
)
from tools import *


# Analyze APK using multiple tools
def analyze(path):
    add_apk_analysis(path)

    file_hash = hash_file(path)

    mobsf_data = mobsf_analysis(path)
    add_tool_analysis("MOBSF_ANALYSIS", mobsf_data, file_hash)

    apkid_data = apkid_analysis(path)
    add_tool_analysis("APKID_ANALYSIS", apkid_data, file_hash)

    ssdeep_analysis(path)

    quark_engine_data = quark_engine_analysis(path)
    add_tool_analysis("QUARK_ENGINE_ANALYSIS", quark_engine_data, file_hash)

    androcfg_data = androcfg_analysis(path)
    add_tool_analysis("ANDROCFG_ANALYSIS", androcfg_data, file_hash)

    virustotal_data = virustotal_analysis(path)
    add_tool_analysis("VIRUSTOTAL_ANALYSIS", virustotal_data, file_hash)

    malwarebazaar_data = malwarebazaar_analysis(path)
    add_tool_analysis("MALWAREBAZAAR_ANALYSIS", malwarebazaar_data, file_hash)

    apk_info_data = apk_info_analysis(path)
    add_tool_analysis("APK_INFO_ANALYSIS", apk_info_data, file_hash)

    yara_data = yara_analysis(path)
    add_tool_analysis("YARA_ANALYSIS", yara_data, file_hash)


if __name__ == "__main__":
    print(
        "initalizeDatabase() took",
        timeit.timeit(lambda: initalizeDatabase(), number=1),
        "seconds",
    )

    if len(sys.argv) == 1:
        print("No path given!")
        exit()

    path = sys.argv[1]
    analyze(path)
    # report_id = hash_file(path)
    # saveReport(report, f"{report_id}.json")
