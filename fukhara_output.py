import json
import sys
from datetime import datetime
from multiprocessing.spawn import prepare
from pathlib import Path

from fastapi import FastAPI

from vt import virustotal


def load_report(id):
    path = f"reports/{id}.json"
    with open(path, "r") as file:
        return json.load(file)


################################################# FINGERPRINTS  #################################################


def prepare_checksums_output(report):
    try:
        mobsf_output = report[1]["tool_results"]

        filesum = {
            "size": mobsf_output["size"],
            "md5": mobsf_output["md5"],
            "sha1": mobsf_output["sha1"],
            "sha256": mobsf_output["sha256"],
        }

        filesum["computed_with"] = "mobsf"

        return filesum
    except:
        return {}


def prepare_apkid_output(report):
    try:
        apkid_output = report[2]["tool_results"]
        apkid = {"files": apkid_output["files"]}

        apkid["computed_with"] = "apkid"

        return apkid
    except:
        return {}


def prepare_ssdeep_output(report):
    try:
        ssdeep_output = report[3]["tool_results"]
        ssdeep = {"apk_file": ssdeep_output[0]["blocksize:hash:hash"]}

        ssdeep["computed_with"] = "ssdeep"

        return ssdeep
    except:
        return {}


def prepare_fingerprints_output(report):
    checksums = prepare_checksums_output(report)
    identifiers = [prepare_apkid_output(report)]
    fuzzy_hashes = [prepare_ssdeep_output(report)]

    fingerprints = {
        "checksums": checksums,
        "identifiers": identifiers,
        "fuzzy_hashes": fuzzy_hashes,
    }

    return fingerprints


################################################# THREAT INTELLIGENCE  #################################################


def prepare_sample_timeline_output(report):
    try:
        upload_timestamp = report[0]["upload_to_fukhara_timestamp"]
        virustotal_output = report[6]["tool_results"]["attributes"]

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

        sample_timeline["computed_with"] = "virustotal"

        return sample_timeline
    except:
        return {}


def prepare_virustotal_output(report):
    try:
        virustotal_output = {"output": report[6]["tool_results"]["attributes"]}

        virustotal_output["computed_with"] = "virustotal"

        return virustotal_output
    except:
        return {}


def prepare_malwarebazaar_output(report):
    try:
        malwarebazaar_output = {"output": report[7]["tool_results"]}

        malwarebazaar_output["computed_with"] = "malwarebazaar"

        return malwarebazaar_output
    except:
        return {}


def prepare_yara_analysis_output(report):
    try:
        yara_analysis_output = report[9]["tool_results"]

        yara_matches = {"matches": yara_analysis_output["matches"]}

        yara_matches["computed_with"] = "yara_analysis"

        return yara_matches
    except:
        return {}


def prepare_threat_intelligence_output(report):
    sample_timeline = prepare_sample_timeline_output(report)
    virustotal = prepare_virustotal_output(report)
    malwarebazaar = prepare_malwarebazaar_output(report)
    yara_analysis = prepare_yara_analysis_output(report)

    threat_intelligence = {
        "sample_timeline": sample_timeline,
        "yara_matches": yara_analysis,
        "av-detections": {},
        "third-party-apps": {
            "virustotal": virustotal,
            "malwarebazaar": malwarebazaar,
        },
    }

    return threat_intelligence


################################################# APPLICATION ANALYSIS  #################################################


def prepare_apk_details_output(report):
    try:
        mobsf_output = report[1]["tool_results"]
        apk_info = report[8]["tool_results"]
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

        apk_details["computed_with"] = ["mobsf", "apk_info"]

        return apk_details
    except:
        return {}


def prepare_certificate_details_output(report):
    try:
        apk_info = report[8]["tool_results"]
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

        certificate_details["computed_with"] = "apk_info"

        return certificate_details
    except:
        return {}


def prepare_manifest_analysis_output(report):
    try:
        mobsf_output = report[1]["tool_results"]

        manifest_analysis = {
            "manifests": mobsf_output["manifest_analysis"]["manifest_findings"]
        }

        manifest_analysis["computed_with"] = "mobsf"

        return manifest_analysis
    except:
        return {}


def prepare_activities_output(report):
    try:
        mobsf_output = report[1]["tool_results"]

        main_activity = {"main_activity": mobsf_output["main_activity"]}
        main_activity["computed_with"] = "mobsf"

        all_activities = {"all_activities": mobsf_output["activities"]}
        all_activities["computed_with"] = "mobsf"

        activities = {
            "main_activity": main_activity,
            "all_activities": all_activities,
        }

        return activities
    except:
        return {}


def prepare_receivers_output(report):
    try:
        mobsf_output = report[1]["tool_results"]

        receivers = {"receivers": mobsf_output["receivers"]}
        receivers["computed_with"] = "mobsf"

        return receivers
    except:
        return {}


def prepare_services_output(report):
    try:
        mobsf_output = report[1]["tool_results"]

        services = {"services": mobsf_output["services"]}
        services["computed_with"] = "mobsf"

        return services
    except:
        return {}


def prepare_apk_analysis_output(report):
    apk_details = prepare_apkid_output(report)
    certificate_details = prepare_certificate_details_output(report)
    manifest_analysis = prepare_manifest_analysis_output(report)
    activities = prepare_activities_output(report)
    receivers = prepare_receivers_output(report)
    services = prepare_services_output(report)

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


def prepare_niap_analysis_output(report):
    try:
        mobsf_output = report[1]["tool_results"]
        niap_analysis = mobsf_output["niap_analysis"]

        niap_analysis["computed_with"] = "mobsf"

        return niap_analysis
    except:
        return {}


def prepare_code_vulnerabilities_output(report):
    try:
        mobsf_output = report[1]["tool_results"]
        code_analysis = mobsf_output["code_analysis"]["findings"]

        code_analysis["computed_with"] = "mobsf"

        return code_analysis
    except:
        return {}


def prepare_code_analysis_output(report):
    niap_analysis = prepare_niap_analysis_output(report)
    code_vulnerabilities = prepare_code_vulnerabilities_output(report)

    code_analysis = {
        "niap_analysis": niap_analysis,
        "code_vulnerabilties": code_vulnerabilities,
    }

    return code_analysis


################################################# BEHAVIOR ANALYSIS  #################################################


def prepare_threat_analysis_output(report):
    try:
        quark_engine_output = report[3]["tool_results"]
        crimes = quark_engine_output["crimes"]

        threats = []
        for c in crimes:
            crime = c["crime"]
            confidence = c["confidence"]

            threats.append({"crime": crime, "confidence": confidence})

        threat_analysis = {"threats": threats}

        threat_analysis["computed_with"] = "quark_engine"

        return threat_analysis
    except:
        return {}


def prepare_permission_analysis_output(report):
    try:
        mobsf_output = report[1]["tool_results"]
        permission_analysis = {"permissions": mobsf_output["permissions"]}

        permission_analysis["computed_with"] = "mobsf"

        return permission_analysis
    except:
        return {}


def prepare_detailed_permissions_analysis_output(report):
    try:
        mobsf_output = report[1]["tool_results"]
        detailed_permissions = {"detailed_permissions": mobsf_output["android_api"]}

        detailed_permissions["computed_with"] = "mobsf"

        return detailed_permissions
    except:
        return {}


def prepare_behavior_analysis_output(report):
    threat_analysis = prepare_threat_analysis_output(report)
    permission_analysis = prepare_permission_analysis_output(report)
    detailed_permissions_analysis = prepare_detailed_permissions_analysis_output(report)

    behavior_analysis = {
        "threats": threat_analysis,
        "permissions": permission_analysis,
        "detailed_permissions": detailed_permissions_analysis,
    }

    return behavior_analysis


################################################# NETWORK ANALYSIS  #################################################


def prepare_domain_analysis_output(report):
    try:
        mobsf_output = report[1]["tool_results"]
        domains = {"domains": mobsf_output["domains"]}

        domains["computed_with"] = "mobsf"

        return domains
    except:
        return {}


def prepare_url_analysis_output(report):
    try:
        mobsf_output = report[1]["tool_results"]
        urls = {"urls": mobsf_output["urls"]}

        urls["computed_with"] = "mobsf"

        return urls
    except:
        return {}


def prepare_network_analysis_output(report):
    domains = prepare_domain_analysis_output(report)
    urls = prepare_url_analysis_output(report)

    network_analysis = {"domains": domains, "urls": urls}

    return network_analysis


################################################# FULL REPORT  #################################################


def prepare_report_output(report):
    fingerprints = prepare_fingerprints_output(report)
    threat_intelligence = prepare_threat_intelligence_output(report)
    apk_analysis = prepare_apk_analysis_output(report)
    code_analysis = prepare_code_analysis_output(report)
    behavior_analysis = prepare_behavior_analysis_output(report)
    network_analysis = prepare_network_analysis_output(report)

    report = {
        "fingerprints": fingerprints,
        "threat_intelligence": threat_intelligence,
        "apk_analysis": apk_analysis,
        "code_analysis": code_analysis,
        "behavior_analysis": behavior_analysis,
        "network_analysis": network_analysis,
    }

    return report


################################################# API  #################################################

app = FastAPI()


# GET all reports
@app.get("/api/reports/")
async def get_reports():
    files = [f.stem for f in Path("reports").iterdir() if f.is_file()]
    return json.dumps(files)


# GET full Report
@app.get("/api/report/{id}/")
async def get_report(id):
    report = load_report(id)

    data = prepare_report_output(report)
    json_data = json.dumps(data)

    return json_data


##########################################################################


# GET fingerprints
@app.get("/api/report/{id}/fingerprints/")
async def get_fingerprints(id):
    report = load_report(id)

    data = prepare_fingerprints_output(report)
    json_data = json.dumps(data)

    return json_data


# GET checksums
@app.get("/api/report/{id}/fingerprints/checksums/")
async def get_checksums(id):
    report = load_report(id)

    data = prepare_checksums_output(report)
    json_data = json.dumps(data)

    return json_data


# GET identifiers
@app.get("/api/report/{id}/fingerprints/identifiers/")
async def get_identifiers(id):
    report = load_report(id)

    data = [prepare_apk_analysis_output(report)]
    json_data = json.dumps(data)

    return json_data


# GET fuzzy hashes
@app.get("/api/report/{id}/fingerprints/fuzzy-hashes/")
async def get_fuzzy_hashes(id):
    report = load_report(id)

    data = [prepare_ssdeep_output(report)]
    json_data = json.dumps(data)

    return json_data


##########################################################################


# GET threat intelligence
@app.get("/api/report/{id}/threat-intelligence/")
async def get_threat_intelligence(id):
    report = load_report(id)

    data = prepare_threat_intelligence_output(report)
    json_data = json.dumps(data)

    return json_data


# GET sample timeline
@app.get("/api/report/{id}/threat-intelligence/timeline/")
async def get_sample_timeline(id):
    report = load_report(id)

    data = prepare_sample_timeline_output(report)
    json_data = json.dumps(data)

    return json_data


# GET yara matches
@app.get("/api/report/{id}/threat-intelligence/yara/")
async def get_yara_analysis(id):
    report = load_report(id)

    data = prepare_yara_analysis_output(report)
    json_data = json.dumps(data)

    return json_data


# GET antivirus detections
@app.get("/api/report/{id}/threat-intelligence/av-detections/")
async def get_antivirus_detections(id):
    report = load_report(id)

    data = {}
    json_data = json.dumps(data)

    return json_data


# GET third party apps
@app.get("/api/report/{id}/threat-intelligence/third-party-apps/")
async def get_third_party_apps(id):
    report = load_report(id)

    data = {
        "virustotal": prepare_virustotal_output(report),
        "malwarebazaar": prepare_malwarebazaar_output(report),
    }
    json_data = json.dumps(data)

    return json_data


##########################################################################


# GET app info
@app.get("/api/report/{id}/app/")
async def get_app_analysis(id):
    report = load_report(id)

    data = prepare_code_analysis_output(report)
    json_data = json.dumps(data)

    return json_data


# GET app details
@app.get("/api/report/{id}/app/details/")
async def get_app_details(id):
    report = load_report(id)

    data = prepare_apk_details_output(report)
    json_data = json.dumps(data)

    return json_data


# GET app certificate
@app.get("/api/report/{id}/app/certificate/")
async def get_app_certificate(id):
    report = load_report(id)

    data = prepare_certificate_details_output(report)
    json_data = json.dumps(data)

    return json_data


# GET app manifests
@app.get("/api/report/{id}/app/manifests/")
async def get_app_manifests(id):
    report = load_report(id)

    data = prepare_manifest_analysis_output(report)
    json_data = json.dumps(data)

    return json_data


# GET app activities
@app.get("/api/report/{id}/app/activities/")
async def get_app_activities(id):
    report = load_report(id)

    data = prepare_activities_output(report)
    json_data = json.dumps(data)

    return json_data


# GET app receiver
@app.get("/api/report/{id}/app/receivers/")
async def get_app_receivers(id):
    report = load_report(id)

    data = prepare_receivers_output(report)
    json_data = json.dumps(data)

    return json_data


# GET app services
@app.get("/api/report/{id}/app/services/")
async def get_app_services(id):
    report = load_report(id)

    data = prepare_services_output(report)
    json_data = json.dumps(data)

    return json_data


##########################################################################


# GET code analysis
@app.get("/api/report/{id}/code/")
async def get_code_analysis(id):
    report = load_report(id)

    data = prepare_code_analysis_output(report)
    json_data = json.dumps(data)

    return json_data


# GET NIAP analysis
@app.get("/api/report/{id}/code/niap/")
async def get_niap_analysis(id):
    report = load_report(id)

    data = prepare_niap_analysis_output(report)
    json_data = json.dumps(data)

    return json_data


# GET code vulnerabilities
@app.get("/api/report/{id}/code/vulnerabilities/")
async def get_code_vulnerabilities(id):
    report = load_report(id)

    data = prepare_code_vulnerabilities_output(report)
    json_data = json.dumps(data)

    return json_data


##########################################################################


# GET behavior analysis
@app.get("/api/report/{id}/behavior/")
async def get_behavior_analysis(id):
    report = load_report(id)

    data = prepare_behavior_analysis_output(report)
    json_data = json.dumps(data)

    return json_data


# GET threat analysis
@app.get("/api/report/{id}/behavior/threats/")
async def get_threats_analysis(id):
    report = load_report(id)

    data = prepare_threat_analysis_output(report)
    json_data = json.dumps(data)

    return json_data


# GET permission analysis
@app.get("/api/report/{id}/behavior/permissions/")
async def get_permission_analysis(id):
    report = load_report(id)

    data = prepare_permission_analysis_output(report)
    json_data = json.dumps(data)

    return json_data


# GET detailed permission analysis
@app.get("/api/report/{id}/behavior/detailed-permissions/")
async def get_detailed_permissions(id):
    report = load_report(id)

    data = prepare_detailed_permissions_analysis_output(report)
    json_data = json.dumps(data)

    return json_data


##########################################################################


@app.get("/api/report/{id}/control-flow/")
async def get_control_flow(id):
    report = load_report(id)
    output = json.dumps({})
    return output


##########################################################################


# GET network analysis
@app.get("/api/report/{id}/network/")
async def get_network_analysis(id):
    report = load_report(id)

    data = prepare_network_analysis_output(report)
    json_data = json.dumps(data)

    return json_data


# GET domain analysis
@app.get("/api/report/{id}/network/domains/")
async def get_domain_analysis(id):
    report = load_report(id)

    data = prepare_domain_analysis_output(report)
    json_data = json.dumps(data)

    return json_data


# GET URL analysis
@app.get("/api/report/{id}/network/urls/")
async def get_url_analysis(id):
    report = load_report(id)

    data = prepare_url_analysis_output(report)
    json_data = json.dumps(data)

    return json_data
