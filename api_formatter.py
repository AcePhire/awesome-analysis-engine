from datetime import datetime

from postgres_handler import (
    get_analysis_upload_timestamp,
    get_fuzzy_hash_analysis,
    get_tool_analysis,
)

from tools import malwarebazaar_analysis


def encapsulate(tool_output, computed_with):
    output = {}
    output["computed_with"] = computed_with
    output["data"] = tool_output

    return output

################################################# VERDICT  #################################################

def prepare_verdict_output(sha256):
    computed_with = ["fukhara"]
    try:
        verdict = {
            "verdict": "",
            "severity": "",
            "reason": "",
            "response": ""
        }
    except Exception:
        verdict = {}

    return encapsulate(verdict, computed_with)

################################################# FINGERPRINTS  #################################################


def prepare_checksums_output(sha256):
    computed_with = ["mobsf"]
    try:
        mobsf_output = get_tool_analysis(sha256, computed_with[0])

        checksums = {
            "size": mobsf_output["size"],
            "md5": mobsf_output["md5"],
            "sha1": mobsf_output["sha1"],
            "sha256": mobsf_output["sha256"],
        }
    except Exception:
        checksums = {}

    return encapsulate(checksums, computed_with)


def prepare_identifers_output(sha256):
    computed_with = ["apkid"]
    try:
        apkid_output = get_tool_analysis(sha256, computed_with[0])
        apkid = {"files": apkid_output}

    except Exception:
        apkid = {}

    identifiers = {"apkid": apkid}

    return encapsulate(identifiers, computed_with)


def prepare_fuzzy_hash_output(sha256):
    computed_with = ["ssdeep"]
    try:
        fuzzy_hashes = {}
        for tool in computed_with:
            tool_output = get_fuzzy_hash_analysis(sha256, tool)
            fuzzy_hashes[tool] = [
                {"filename": item["filename"], "fuzzy_hash": item["fuzzy_hash"]}
                for item in tool_output
            ]
    except Exception:
        fuzzy_hashes = {}

    return encapsulate(fuzzy_hashes, computed_with)


def prepare_fingerprints_output(sha256):
    checksums = prepare_checksums_output(sha256)
    identifers = prepare_identifers_output(sha256)
    fuzzy_hashes = prepare_fuzzy_hash_output(sha256)

    fingerprints = {
        "checksums": checksums,
        "identifiers": identifers,
        "fuzzy_hashes": fuzzy_hashes,
    }

    return fingerprints


################################################# THREAT INTELLIGENCE  #################################################


def prepare_sample_timeline_output(sha256):
    computed_with = ["fukhara", "virustotal"]
    try:
        upload_timestamp = str(get_analysis_upload_timestamp(sha256))
        virustotal_output = get_tool_analysis(sha256, computed_with[1])["data"][
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

    except Exception:
        sample_timeline = {}

    return encapsulate(sample_timeline, computed_with)


def prepare_third_party_apps_output(sha256):
    computed_with = ["virustotal", "malwarebazaar"]

    try:
        virustotal_output = get_tool_analysis(sha256, computed_with[0])["data"]

        virustotal_link = virustotal_output["links"]["self"]
    except Exception:
        virustotal_link = ""

    try:
        get_tool_analysis(sha256, computed_with[1])["data"][0]

        malwarebazaar_link = "https://bazaar.abuse.ch/sample/" + sha256
    except Exception:
        malwarebazaar_link = ""

    third_party_apps = {
        "virustotal": virustotal_link,
        "malwarebazaar": malwarebazaar_link,
    }

    return encapsulate(third_party_apps, computed_with)


def prepare_popular_av_detections_output(sha256):
    computed_with = ["virustotal"]

    try:
        virustotal_output = get_tool_analysis(sha256, computed_with[0])["data"]

        av_detections = virustotal_output["attributes"][
            "popular_threat_classification"
        ]["popular_threat_name"]

        popular_av_detections = []

        for av in av_detections:
            detection = {av["value"]: av["count"]}

            popular_av_detections.append(detection)
    except Exception:
        popular_av_detections = {}

    return encapsulate(popular_av_detections, computed_with)


def prepare_yara_analysis_output(sha256):
    computed_with = ["yara_analyzer"]
    try:
        yara_analysis_output = get_tool_analysis(sha256, computed_with[0])

        yara_matches = {"matches": yara_analysis_output["matches"]}

    except Exception:
        yara_matches = {}

    return encapsulate(yara_matches, computed_with)


def prepare_threat_intelligence_output(sha256):
    sample_timeline = prepare_sample_timeline_output(sha256)
    third_party_apps = prepare_third_party_apps_output(sha256)
    popular_av_detections = prepare_popular_av_detections_output(sha256)
    yara_analysis = prepare_yara_analysis_output(sha256)

    threat_intelligence = {
        "sample_timeline": sample_timeline,
        "yara_matches": yara_analysis,
        "av-detections": popular_av_detections,
        "third-party-apps": third_party_apps,
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

    except Exception:
        apk_details = {}

    return encapsulate(apk_details, computed_with)


def prepare_certificate_details_output(sha256):
    computed_with = ["apk_info"]
    try:
        apk_info = get_tool_analysis(sha256, computed_with[0])
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

    except Exception:
        certificate_details = {}

    return encapsulate(certificate_details, computed_with)


def prepare_manifest_analysis_output(sha256):
    computed_with = ["mobsf"]
    try:
        mobsf_output = get_tool_analysis(sha256, computed_with[0])

        manifest_analysis = mobsf_output["manifest_analysis"]["manifest_findings"]

    except Exception:
        manifest_analysis = {}

    return encapsulate(manifest_analysis, computed_with)


def prepare_activities_output(sha256):
    computed_with = ["mobsf"]
    try:
        mobsf_output = get_tool_analysis(sha256, computed_with[0])

        main_activity = mobsf_output["main_activity"]

        all_activities = mobsf_output["activities"]
    except Exception:
        main_activity = ""
        all_activities = []

    activities = {
        "main_activity": main_activity,
        "all_activities": all_activities,
    }

    return encapsulate(activities, computed_with)


def prepare_receivers_output(sha256):
    computed_with = ["mobsf"]
    try:
        mobsf_output = get_tool_analysis(sha256, computed_with[0])

        receivers = mobsf_output["receivers"]
    except Exception:
        receivers = []

    return encapsulate(receivers, computed_with)


def prepare_services_output(sha256):
    computed_with = ["mobsf"]
    try:
        mobsf_output = get_tool_analysis(sha256, computed_with[0])

        services = mobsf_output["services"]
    except Exception:
        services = []

    return encapsulate(services, computed_with)


def prepare_apk_analysis_output(sha256):
    apk_details = prepare_apk_details_output(sha256)
    certificate_details = prepare_certificate_details_output(sha256)
    manifest_analysis = prepare_manifest_analysis_output(sha256)
    activities = prepare_activities_output(sha256)
    receivers = prepare_receivers_output(sha256)
    services = prepare_services_output(sha256)

    apk_analysis = {
        "apk_details": apk_details,
        "certificate_details": certificate_details,
        "manifest_analysis": manifest_analysis,
        "acitivities": activities,
        "receivers": receivers,
        "services": services,
    }

    return apk_analysis


################################################# CODE ANALYSIS  #################################################


def prepare_niap_analysis_output(sha256):
    computed_with = ["mobsf"]
    try:
        mobsf_output = get_tool_analysis(sha256, computed_with[0])
        niap_analysis = mobsf_output["niap_analysis"]
    except Exception:
        niap_analysis = {}

    return encapsulate(niap_analysis, computed_with)


def prepare_code_vulnerabilities_output(sha256):
    computed_with = ["mobsf"]
    try:
        mobsf_output = get_tool_analysis(sha256, computed_with[0])
        code_analysis = mobsf_output["code_analysis"]["findings"]
    except Exception:
        code_analysis = {}

    return encapsulate(code_analysis, computed_with)


def prepare_code_analysis_output(sha256):
    niap_analysis = prepare_niap_analysis_output(sha256)
    code_vulnerabilities = prepare_code_vulnerabilities_output(sha256)

    code_analysis = {
        "niap_analysis": niap_analysis,
        "code_vulnerabilties": code_vulnerabilities,
    }

    return code_analysis


################################################# BEHAVIOR ANALYSIS  #################################################


def prepare_threat_analysis_output(sha256):
    computed_with = ["quark_engine"]
    try:
        quark_engine_output = get_tool_analysis(sha256, computed_with[0])
        crimes = quark_engine_output["crimes"]

        threat_analysis = []
        for c in crimes:
            crime = c["crime"]
            confidence = c["confidence"]

            threat_analysis.append({"crime": crime, "confidence": confidence})
    except Exception:
        threat_analysis = []

    return encapsulate(threat_analysis, computed_with)


def prepare_permission_analysis_output(sha256):
    computed_with = ["mobsf"]
    try:
        mobsf_output = get_tool_analysis(sha256, computed_with)
        permission_analysis = mobsf_output["permissions"]
    except Exception:
        permission_analysis = {}

    return encapsulate(permission_analysis, computed_with)


def prepare_detailed_permissions_analysis_output(sha256):
    computed_with = ["mobsf"]
    try:
        mobsf_output = get_tool_analysis(sha256, computed_with[0])
        detailed_permissions = mobsf_output["android_api"]
    except Exception:
        detailed_permissions = {}

    return encapsulate(detailed_permissions, computed_with)


def prepare_behavior_analysis_output(sha256):
    threat_analysis = prepare_threat_analysis_output(sha256)
    permission_analysis = prepare_permission_analysis_output(sha256)
    detailed_permissions_analysis = prepare_detailed_permissions_analysis_output(sha256)

    behavior_analysis = {
        "threats": threat_analysis,
        "permissions": permission_analysis,
        "detailed_permissions": detailed_permissions_analysis,
    }

    return behavior_analysis


################################################# NETWORK ANALYSIS  #################################################


def prepare_domain_analysis_output(sha256):
    computed_with = ["mobsf"]
    try:
        mobsf_output = get_tool_analysis(sha256, computed_with[0])
        domains = mobsf_output["domains"]
    except Exception:
        domains = {}

    return encapsulate(domains, computed_with)


def prepare_url_analysis_output(sha256):
    computed_with = ["mobsf"]
    try:
        mobsf_output = get_tool_analysis(sha256, computed_with[0])
        urls = mobsf_output["urls"]
    except Exception:
        urls = []

    return encapsulate(urls, computed_with)


def prepare_network_analysis_output(sha256):
    domains = prepare_domain_analysis_output(sha256)
    urls = prepare_url_analysis_output(sha256)

    network_analysis = {
        "domains": domains,
        "urls": urls,
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
