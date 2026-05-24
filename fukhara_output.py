import sys
import json

def load_report(path):
    with open(path, "r") as file:
        return json.load(file)

def extract_file_sum(report):
    mobsf_output = report[0]["tool_results"]

    filesum = {
        "size": mobsf_output["size"],
        "md5": mobsf_output["md5"],
        "sha1": mobsf_output["sha1"],
        "sha256": mobsf_output["sha256"]
    }

    return filesum

def extract_apkid(report):
    apkid_output = report[1]["tool_results"]
    apkid = apkid_output["files"]

    return apkid

def extract_ssdeep(report):
    ssdeep_output = report[2]["tool_results"]
    ssdeep = {
        "apk_file": ssdeep_output[0]["blocksize:hash:hash"]
    }

    return ssdeep

def extract_niap_analysis(report):
    mobsf_output = report[0]["tool_results"]
    niap_analysis = mobsf_output["niap_analysis"]

    return niap_analysis

def extract_code_vulnerabilities(report):
    mobsf_output = report[0]["tool_results"]
    code_analysis = mobsf_output["code_analysis"]["findings"]

    return code_analysis

def extract_threat_analysis(report):
    quark_engine_output = report[3]["tool_results"]
    crimes = quark_engine_output["crimes"]

    threat_analysis = []
    for c in crimes:
        crime = c["crime"]
        confidence = c["confidence"]

        threat_analysis.append({
            "crime": crime,
            "confidence": confidence
        })
        

    return threat_analysis

def extract_permission_analysis(report):
    mobsf_output = report[0]["tool_results"]
    permission_analysis = mobsf_output["permissions"]

    return permission_analysis

def extract_detailed_permissions(report):
    mobsf_output = report[0]["tool_results"]
    detailed_permissions = mobsf_output["android_api"]

    return detailed_permissions

def extract_domains(report):
    mobsf_output = report[0]["tool_results"]
    domains = mobsf_output["domains"]

    return domains

def extract_urls(report):
    mobsf_output = report[0]["tool_results"]
    urls = mobsf_output["urls"]

    return urls

def extract_apk_details(report):
    mobsf_output = report[0]["tool_results"]
    apk_info = report[7]["tool_results"]
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
        "frosting": frosting_info
    }

    return apk_details

def extract_certificate_details(report):
    apk_info = report[7]["tool_results"]
    google_play_info = apk_info["google_play_info"]
    sign = google_play_info["sign"]

    certificate_details = {
        "md5": sign["certificates"][0]["fingerprint_md5"],
        "sha1": sign["certificates"][0]["fingerprint_sha1"],
        "sha256": sign["certificates"][0]["fingerprint_sha256"],
        "issuer": sign["certificates"][0]["issuer"],
        "not_before": sign["certificates"][0]["not_before"],
        "not_after": sign["certificates"][0]["not_after"]
    }

    return certificate_details

def extract_manifest_analysis(report):
    mobsf_output = report[0]["tool_results"]

    manifest_analysis = mobsf_output["manifest_analysis"]["manifest_findings"]

    return manifest_analysis

def extract_activities(report):
    mobsf_output = report[0]["tool_results"]
    
    main_activity = mobsf_output["main_activity"]

    activities = mobsf_output["activities"]

    receivers = mobsf_output["receivers"]

    services = mobsf_output["services"]

    return main_activity, activities, receivers, services


def extract_sample_timeline(report):
    virustotal_output = report[5]["tool_results"]["attributes"]
    
    sample_timeline = {
        "oldest_file_found_in_apk": virustotal_output["bundle_info"]["lowest_datetime"],
        "certificate_valid_not_before": virustotal_output["androguard"]["certificate"]["validfrom"],
        "latest_file_found_in_apk": virustotal_output["bundle_info"]["highest_datetime"],
        "first_submission_on_vt": virustotal_output["first_submission_date"],
        "last_submission_on_vt": virustotal_output["last_submission_date"],
        "upload_on_fukhara": report[0]["timestamp"],
        "certificate_valid_not_after": virustotal_output["androguard"]["certificate"]["validto"]
    }

def extract_virustotal_results(report):
    virustotal_output = report[5]["tool_results"]["attributes"]

    return virustotal_output

def extract_malwarebazaar_results(report):
    malwarebazaar_output = report[5]["tool_results"]

    return malwarebazaar_output

def extract_yara_analysis(report):
    yara_analysis_output = report[8]["tool_results"]

    yara_matches = yara_analysis_output["matches"]

    return yara_matches

def get_fingerprints(report):
    filesum = extract_file_sum(report)
    apkid = extract_apkid(report)
    ssdeep = extract_ssdeep(report)

    fingerprints = {
        "filesum": filesum,
        "apkid": apkid,
        "ssdeep": ssdeep
    }

    return fingerprints

def get_threat_intelligence(report):
    sample_timeline = extract_sample_timeline(report)
    virustotal = extract_virustotal_results(report)
    malwarebazaar = extract_malwarebazaar_results(report)
    yara_analysis = extract_yara_analysis(report)
    
    threat_intelligence = {
        "sample_timeline": sample_timeline,
        "virustotal": virustotal,
        "malwarebazaar": malwarebazaar,
        "yara_matches": yara_analysis
    }

    return threat_intelligence

def get_apk_analysis(report):
    apk_details = extract_apk_details(report)
    cert_details = extract_certificate_details(report)
    manifest_analysis = extract_manifest_analysis(report)
    main_activity, activities, receivers, services = extract_activities(report)

    apk_analysis = {
        "apk_details": apk_details,
        "certificate_details": cert_details,
        "manifest_analysis": manifest_analysis,
        "main_activity": main_activity,
        "acitivities": activities,
        "receivers": receivers,
        "services": services
    }

    return apk_analysis

def get_code_analysis(report):
    niap_analysis = extract_niap_analysis(report)
    code_vulnerabilities = extract_code_vulnerabilities(report)

    code_analysis = {
        "niap_analysis": niap_analysis,
        "code_vulnerabilties": code_vulnerabilities
    }

    return code_analysis

def get_behavior_analysis(report):
    permission_analysis = extract_permission_analysis(report)
    threat_analysis = extract_threat_analysis(report)
    detailed_permissions = extract_detailed_permissions(report)

    behavior_analysis = {
        "permission_analysis": permission_analysis,
        "threat_analysis": threat_analysis,
        "detailed_permissions": detailed_permissions 
    }

    return behavior_analysis

def get_network_analysis(report):
    domains = extract_domains(report)
    urls = extract_urls(report)

    network_analysis = {
        "domains": domains,
        "urls": urls
    }

    return network_analysis

def get_report_info(report):
    fingerprints = get_fingerprints(report)
    threat_intelligence = get_threat_intelligence(report)
    apk_analysis = get_apk_analysis(report)
    code_analysis = get_code_analysis(report)
    behavior_analysis = get_behavior_analysis(report)
    network_analysis = get_network_analysis(report)

    report = {
        "fingerprints": fingerprints,
        "threat_intelligence": threat_intelligence,
        "apk_analysis": apk_analysis,
        "code_analysis": code_analysis,
        "behavior_analysis": behavior_analysis,
        "network_analysis": network_analysis
    }

    return report

if __name__ == "__main__":
    path = sys.argv[1]

    report = load_report(path)
    print(json.dumps(get_report_info(report)))
