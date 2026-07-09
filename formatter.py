from datetime import datetime

from mongodb_handler import (
    get_analysis_upload_timestamp,
    get_fuzzy_hash_analysis,
    get_tool_analysis,
)

################################################# FINGERPRINTS  #################################################


def prepare_checksums_output(sha256):
    computed_with = "mobsf"
    try:
        mobsf_output = get_tool_analysis(sha256, computed_with)

        filesum = {
            "size": mobsf_output["size"],
            "md5": mobsf_output["md5"],
            "sha1": mobsf_output["sha1"],
            "sha256": mobsf_output["sha256"],
        }

        return filesum, computed_with
    except Exception:
        return {}, computed_with


def prepare_apkid_output(sha256):
    computed_with = "apkid"
    try:
        apkid_output = get_tool_analysis(sha256, computed_with)
        apkid = {"files": apkid_output}

        return apkid, computed_with
    except Exception:
        return {}, computed_with


def prepare_fuzzy_hash_output(sha256):
    computed_with = ["ssdeep"]
    try:
        fuzzy_hashes = {}
        for tool in computed_with:
            tool_output = get_fuzzy_hash_analysis(sha256, tool)
            fuzzy_hashes[tool] = {
                item["filename"]: item["fuzzy_hash"] for item in tool_output
            }

        return fuzzy_hashes, computed_with
    except Exception:
        return {}, computed_with


def prepare_fingerprints_output(sha256):
    checksums = prepare_checksums_output(sha256)
    apkid = prepare_apkid_output(sha256)
    fuzzy_hashes = prepare_fuzzy_hash_output(sha256)

    fingerprints = {
        f"checksums[{checksums[1]}]": checksums[0],
        f"identifiers[{apkid[1]}]": {"apkid": apkid[0]},
        f"fuzzy_hashes[{fuzzy_hashes[1]}]": fuzzy_hashes[0],
    }

    return fingerprints


################################################# THREAT INTELLIGENCE  #################################################


def prepare_sample_timeline_output(sha256):
    computed_with = ["fukhara", "virustotal"]
    try:
        upload_timestamp = get_analysis_upload_timestamp(sha256)
        virustotal_output = get_tool_analysis(sha256, "virustotal")["data"][
            "attributes"
        ]

        sample_timeline = {
            "oldest_file_found_in_apk": virustotal_output["bundle_info"][
                "lowest_datetime"
            ],
            "certificate_valid_not_before": virustotal_output["androguard"][
                "certificate"
            ]["validfrom"],
            "latest_file_found_in_apk": virustotal_output["bundle_info"][
                "highest_datetime"
            ],
            "first_submission_on_vt": str(
                datetime.fromtimestamp(virustotal_output["first_submission_date"])
            ),
            "last_submission_on_vt": str(
                datetime.fromtimestamp(virustotal_output["last_submission_date"])
            ),
            "upload_on_fukhara": upload_timestamp,
            "certificate_valid_not_after": virustotal_output["androguard"][
                "certificate"
            ]["validto"],
        }

        return sample_timeline, computed_with
    except Exception:
        return {}, computed_with


def prepare_virustotal_output(sha256):
    computed_with = "virustotal"
    try:
        virustotal_output = get_tool_analysis(sha256, computed_with)["data"]

        return virustotal_output, computed_with
    except Exception:
        return {}, computed_with


def prepare_malwarebazaar_output(sha256):
    computed_with = "malwarebazaar"
    try:
        malwarebazaar_output = get_tool_analysis(sha256, computed_with)["data"]

        return malwarebazaar_output, computed_with
    except Exception:
        return {}, computed_with


def prepare_yara_analysis_output(sha256):
    computed_with = "yara"
    try:
        yara_analysis_output = get_tool_analysis(sha256, computed_with)

        yara_matches = {"matches": yara_analysis_output["matches"]}

        return yara_matches, computed_with
    except Exception:
        return {}, computed_with


def prepare_threat_intelligence_output(sha256):
    sample_timeline = prepare_sample_timeline_output(sha256)
    virustotal = prepare_virustotal_output(sha256)
    malwarebazaar = prepare_malwarebazaar_output(sha256)
    yara_analysis = prepare_yara_analysis_output(sha256)

    threat_intelligence = {
        f"sample_timeline[{sample_timeline[1]}]": sample_timeline[0],
        f"yara_matches[{yara_analysis[1]}]": yara_analysis[0],
        "av-detections": {},
        "third-party-apps": {
            f"virustotal[{virustotal[1]}]": virustotal[0],
            f"malwarebazaar[{malwarebazaar[1]}]": malwarebazaar[0],
        },
    }

    return threat_intelligence


################################################# APPLICATION ANALYSIS  #################################################


def prepare_apk_details_output(sha256):
    computed_with = ["mobsf", "apk_info"]
    try:
        mobsf_output = get_tool_analysis(sha256, computed_with[0])
        apk_info = get_tool_analysis(sha256, computed_with[1])
        frosting_info = apk_info["frosting_info"]
        google_play_info = apk_info["google_play_info"]
        sign = google_play_info["sign"]

        apk_details = {
            "package": sign["handle"],
            "app_name": sign["app_name"],
            "version_name": sign["version_name"],
            "version_code": sign["version_code"],
            "sdk": f"{sign['min_sdk_version']} - {sign['max_sdk_version']}",
            "uaid": sign["uaid"],
            "signature": mobsf_output["certificate_analysis"]["certificate_info"],
            "frosting": frosting_info,
        }

        return apk_details, computed_with
    except Exception:
        return {}, computed_with


def prepare_certificate_details_output(sha256):
    computed_with = "apk_info"
    try:
        apk_info = get_tool_analysis(sha256, computed_with)
        google_play_info = apk_info["google_play_info"]
        sign = google_play_info["sign"]

        certificate_details = {
            "md5": sign["certificates"][0]["fingerprint_md5"],
            "sha1": sign["certificates"][0]["fingerprint_sha1"],
            "sha256": sign["certificates"][0]["fingerprint_sha256"],
            "issuer": sign["certificates"][0]["issuer"],
            "not_before": sign["certificates"][0]["not_before"],
            "not_after": sign["certificates"][0]["not_after"],
        }

        return certificate_details, computed_with
    except Exception:
        return {}, computed_with


def prepare_manifest_analysis_output(sha256):
    computed_with = "mobsf"
    try:
        mobsf_output = get_tool_analysis(sha256, computed_with)

        manifest_analysis = mobsf_output["manifest_analysis"]["manifest_findings"]

        return manifest_analysis, computed_with
    except Exception:
        return {}, computed_with


def prepare_activities_output(sha256):
    computed_with = "mobsf"
    try:
        mobsf_output = get_tool_analysis(sha256, computed_with)

        main_activity = {"main_activity": mobsf_output["main_activity"]}

        all_activities = {"all_activities": mobsf_output["activities"]}

        activities = {
            "main_activity": main_activity,
            "all_activities": all_activities,
        }

        return activities, computed_with
    except Exception:
        return {}, computed_with


def prepare_receivers_output(sha256):
    computed_with = "mobsf"
    try:
        mobsf_output = get_tool_analysis(sha256, computed_with)

        receivers = mobsf_output["receivers"]

        return receivers, computed_with
    except Exception:
        return {}, computed_with


def prepare_services_output(sha256):
    computed_with = "mobsf"
    try:
        mobsf_output = get_tool_analysis(sha256, computed_with)

        services = mobsf_output["services"]

        return services, computed_with
    except Exception:
        return {}, computed_with


def prepare_apk_analysis_output(sha256):
    apk_details = prepare_apk_details_output(sha256)
    certificate_details = prepare_certificate_details_output(sha256)
    manifest_analysis = prepare_manifest_analysis_output(sha256)
    activities = prepare_activities_output(sha256)
    receivers = prepare_receivers_output(sha256)
    services = prepare_services_output(sha256)

    apk_analysis = {
        f"apk_details[{apk_details[1]}]": apk_details[0],
        f"certificate_details[{certificate_details[1]}]": certificate_details[0],
        f"manifest_analysis[{manifest_analysis[1]}]": manifest_analysis[0],
        f"acitivities[{activities[1]}]": activities[0],
        f"receivers[{receivers[1]}]": receivers[0],
        f"services[{services[1]}]": services[0],
    }

    return apk_analysis


################################################# CODE ANALYSIS  #################################################


def prepare_niap_analysis_output(sha256):
    computed_with = "mobsf"
    try:
        mobsf_output = get_tool_analysis(sha256, computed_with)
        niap_analysis = mobsf_output["niap_analysis"]

        return niap_analysis, computed_with
    except Exception:
        return {}, computed_with


def prepare_code_vulnerabilities_output(sha256):
    computed_with = "mobsf"
    try:
        mobsf_output = get_tool_analysis(sha256, computed_with)
        code_analysis = mobsf_output["code_analysis"]["findings"]

        return code_analysis, computed_with
    except Exception:
        return {}, computed_with


def prepare_code_analysis_output(sha256):
    niap_analysis = prepare_niap_analysis_output(sha256)
    code_vulnerabilities = prepare_code_vulnerabilities_output(sha256)

    code_analysis = {
        f"niap_analysis[{niap_analysis[1]}]": niap_analysis[0],
        f"code_vulnerabilties[{code_vulnerabilities[1]}]": code_vulnerabilities[0],
    }

    return code_analysis


################################################# BEHAVIOR ANALYSIS  #################################################


def prepare_threat_analysis_output(sha256):
    computed_with = "quark_engine"
    try:
        quark_engine_output = get_tool_analysis(sha256, computed_with)
        crimes = quark_engine_output["crimes"]

        threats = []
        for c in crimes:
            crime = c["crime"]
            confidence = c["confidence"]

            threats.append({"crime": crime, "confidence": confidence})

        threat_analysis = threats

        return threat_analysis, computed_with
    except Exception:
        return {}, computed_with


def prepare_permission_analysis_output(sha256):
    computed_with = "mobsf"
    try:
        mobsf_output = get_tool_analysis(sha256, computed_with)
        permission_analysis = mobsf_output["permissions"]

        return permission_analysis, computed_with
    except Exception:
        return {}, computed_with


def prepare_detailed_permissions_analysis_output(sha256):
    computed_with = "mobsf"
    try:
        mobsf_output = get_tool_analysis(sha256, computed_with)
        detailed_permissions = mobsf_output["android_api"]

        return detailed_permissions, computed_with
    except Exception:
        return {}, computed_with


def prepare_behavior_analysis_output(sha256):
    threat_analysis = prepare_threat_analysis_output(sha256)
    permission_analysis = prepare_permission_analysis_output(sha256)
    detailed_permissions_analysis = prepare_detailed_permissions_analysis_output(sha256)

    behavior_analysis = {
        f"threats[{threat_analysis[1]}]": threat_analysis[0],
        f"permissions[{permission_analysis[1]}]": permission_analysis[0],
        f"detailed_permissions[{detailed_permissions_analysis[1]}]": detailed_permissions_analysis[
            0
        ],
    }

    return behavior_analysis


################################################# NETWORK ANALYSIS  #################################################


def prepare_domain_analysis_output(sha256):
    computed_with = "mobsf"
    try:
        mobsf_output = get_tool_analysis(sha256, computed_with)
        domains = mobsf_output["domains"]

        return domains, computed_with
    except Exception:
        return {}, computed_with


def prepare_url_analysis_output(sha256):
    computed_with = "mobsf"
    try:
        mobsf_output = get_tool_analysis(sha256, computed_with)
        urls = mobsf_output["urls"]

        return urls, computed_with
    except Exception:
        return {}, computed_with


def prepare_network_analysis_output(sha256):
    domains = prepare_domain_analysis_output(sha256)
    urls = prepare_url_analysis_output(sha256)

    network_analysis = {
        f"domains[{domains[1]}]": domains[0],
        f"urls[{urls[1]}]": urls[0],
    }

    return network_analysis


################################################# FULL REPORT  #################################################


def prepare_report_output(sha256):
    fingerprints = prepare_fingerprints_output(sha256)
    threat_intelligence = prepare_threat_intelligence_output(sha256)
    apk_analysis = prepare_apk_analysis_output(sha256)
    code_analysis = prepare_code_analysis_output(sha256)
    behavior_analysis = prepare_behavior_analysis_output(sha256)
    network_analysis = prepare_network_analysis_output(sha256)

    report = {
        "fingerprints": fingerprints,
        "threat_intelligence": threat_intelligence,
        "apk_analysis": apk_analysis,
        "code_analysis": code_analysis,
        "behavior_analysis": behavior_analysis,
        "network_analysis": network_analysis,
    }

    return report
