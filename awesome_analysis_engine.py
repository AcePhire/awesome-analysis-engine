import asyncio

from postgres_handler import (
    add_fuzzy_hash,
    add_tool_analysis,
    create_apk_analysis,
    set_analysis_status,
)
from tools import *
from utils import hash_file


async def run_analysis_tool(analysis_func, name, path):
    file_hash = hash_file(path)
    result = await asyncio.to_thread(analysis_func, path)
    add_tool_analysis(file_hash, name, result)


async def run_fuzzy_hashes_analysis(fuzzy_hash_func, name, path):
    file_hash = hash_file(path)
    fuzzy_hashes = await asyncio.to_thread(fuzzy_hash_func, path)
    for fuzzy_hash in fuzzy_hashes:
        add_fuzzy_hash(file_hash, name, fuzzy_hash[0], fuzzy_hash[1])


# Analyze APK using multiple tools
async def analyze(path):
    file_hash = create_apk_analysis(path) 

    await asyncio.gather(
        run_analysis_tool(mobsf_analysis, "mobsf", path),
        run_analysis_tool(apkid_analysis, "apkid", path),
        run_fuzzy_hashes_analysis(ssdeep_analysis, "ssdeep", path),
        run_analysis_tool(quark_engine_analysis, "quark_engine", path),
        run_analysis_tool(androcfg_analysis, "androcfg", path),
        run_analysis_tool(virustotal_analysis, "virustotal", path),
        run_analysis_tool(malwarebazaar_analysis, "malwarebazaar", path),
        run_analysis_tool(apk_info_analysis, "apk_info", path),
        run_analysis_tool(yara_analysis, "yara", path),
    )

    set_analysis_status(file_hash, "completed")
