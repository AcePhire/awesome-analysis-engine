import sys

from postgres_handler import (
    add_apk_analysis,
    initalizeDatabase,
)
from tools import *


# Analyze APK using multiple tools
def analyze(path):
    add_apk_analysis(path)

    mobsf_analysis(path)
    apkid_analysis(path)
    ssdeep_analysis(path)
    quark_engine_analysis(path)
    androcfg_analysis(path)
    virustotal_analysis(path)
    malwarebazaar_analysis(path)
    apk_info_analysis(path)
    yara_analysis(path)


if __name__ == "__main__":
    initalizeDatabase()

    if len(sys.argv) == 1:
        print("No path given!")
        exit()

    path = sys.argv[1]
    analyze(path)
    # report_id = hash_file(path)
    # saveReport(report, f"{report_id}.json")
