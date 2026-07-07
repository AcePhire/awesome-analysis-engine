import asyncio
import json
import shutil
from collections.abc import AsyncIterable

from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.sse import EventSourceResponse, ServerSentEvent

from awesome_analysis_engine import analyze
from formatter import *
from mongodb_handler import (
    get_analysis_status,
    list_apk_analyses,
)

# from ssdeep_compare import hash_compare
from utils import hash_file

################################################# API  #################################################

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# HOME
@app.get("/")
async def home():
    return FileResponse("upload.html")


# POST apk analysis
@app.post("/api/analyze/")
async def analyze_apk(file: UploadFile = File(...)):
    path = f"apk_files/{file.filename}"

    with open(path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    sha256 = hash_file(path)
    asyncio.create_task(analyze(path))

    return {"status": "success", "id": sha256}


# SSDeep Compare
# @app.get("/compare/ssdeep/{id}")
# async def compare_ssdeep_hashes(id):
# return hash_compare(id)


# GET all reports
@app.get("/api/reports/")
async def get_reports():
    return list_apk_analyses()


# GET full Report
@app.get("/api/report/{id}/", response_class=EventSourceResponse)
async def get_report(id) -> AsyncIterable[ServerSentEvent]:
    data = prepare_report_output(id)

    while get_analysis_status(id) == "pending":
        yield ServerSentEvent(raw_data=json.dumps(data))
        await asyncio.sleep(5)
    yield ServerSentEvent(raw_data=json.dumps(data))


##########################################################################


# GET fingerprints
@app.get("/api/report/{id}/fingerprints/")
async def get_fingerprints(id):
    data = prepare_fingerprints_output(id)

    return data


# GET checksums
@app.get("/api/report/{id}/fingerprints/checksums/")
async def get_checksums(id):
    output, computed_with = prepare_checksums_output(id)

    data = {f"checksums[{computed_with}]": output}

    return data


# GET identifiers
@app.get("/api/report/{id}/fingerprints/identifiers/")
async def get_identifiers(id):
    output, computed_with = prepare_apkid_output(id)

    data = {f"identifiers[{computed_with}]": [output]}

    return data


# GET fuzzy hashes
@app.get("/api/report/{id}/fingerprints/fuzzy-hashes/")
async def get_fuzzy_hashes(id):
    output, computed_with = prepare_fuzzy_hash_output(id)

    data = {f"fuzzy-hashes[{computed_with}]": output}

    return data


##########################################################################


# GET threat intelligence
@app.get("/api/report/{id}/threat-intelligence/")
async def get_threat_intelligence(id):
    data = prepare_threat_intelligence_output(id)

    return data


# GET sample timeline
@app.get("/api/report/{id}/threat-intelligence/timeline/")
async def get_sample_timeline(id):
    output, computed_with = prepare_sample_timeline_output(id)
    data = {f"sample_timeline[{computed_with}]": output}

    return data


# GET yara matches
@app.get("/api/report/{id}/threat-intelligence/yara/")
async def get_yara_analysis(id):
    output, computed_with = prepare_yara_analysis_output(id)

    data = {f"yara_matches[{computed_with}]": output}

    return data


# GET antivirus detections
@app.get("/api/report/{id}/threat-intelligence/av-detections/")
async def get_antivirus_detections(id):
    data = {}
    json_data = json.dumps(data)

    return json_data


# GET third party apps
@app.get("/api/report/{id}/threat-intelligence/third-party-apps/")
async def get_third_party_apps(id):
    virustotal_output = prepare_virustotal_output(id)
    malwarebazaar_output = prepare_malwarebazaar_output(id)
    data = {
        "third-party-apps": {
            f"virustotal[{virustotal_output[1]}]": virustotal_output[0],
            f"malwarebazaar[{malwarebazaar_output[1]}]": malwarebazaar_output[0],
        }
    }

    return data


##########################################################################


# GET app info
@app.get("/api/report/{id}/app/")
async def get_app_analysis(id):
    data = prepare_apk_analysis_output(id)

    return data


# GET app details
@app.get("/api/report/{id}/app/details/")
async def get_app_details(id):
    output, computed_with = prepare_apk_details_output(id)
    data = {
        f"apk_details[{computed_with}]": output,
    }

    return data


# GET app certificate
@app.get("/api/report/{id}/app/certificate/")
async def get_app_certificate(id):
    output, computed_with = prepare_certificate_details_output(id)
    data = {
        f"certificate_details[{computed_with}]": output,
    }

    return data


# GET app manifests
@app.get("/api/report/{id}/app/manifests/")
async def get_app_manifests(id):
    output, computed_with = prepare_manifest_analysis_output(id)
    data = {
        f"manifest_analysis[{computed_with}]": output,
    }

    return data


# GET app activities
@app.get("/api/report/{id}/app/activities/")
async def get_app_activities(id):
    output, computed_with = prepare_activities_output(id)
    data = {
        f"activities[{computed_with}]": output,
    }

    return data


# GET app receiver
@app.get("/api/report/{id}/app/receivers/")
async def get_app_receivers(id):
    output, computed_with = prepare_receivers_output(id)
    data = {
        f"receivers[{computed_with}]": output,
    }

    return data


# GET app services
@app.get("/api/report/{id}/app/services/")
async def get_app_services(id):
    output, computed_with = prepare_services_output(id)
    data = {
        f"services[{computed_with}]": output,
    }

    return data


##########################################################################


# GET code analysis
@app.get("/api/report/{id}/code/")
async def get_code_analysis(id):
    data = prepare_code_analysis_output(id)

    return data


# GET NIAP analysis
@app.get("/api/report/{id}/code/niap/")
async def get_niap_analysis(id):
    output, computed_with = prepare_niap_analysis_output(id)
    data = {f"niap_analysis[{computed_with}]": output}

    return data


# GET code vulnerabilities
@app.get("/api/report/{id}/code/vulnerabilities/")
async def get_code_vulnerabilities(id):
    output, computed_with = prepare_code_vulnerabilities_output(id)
    data = {f"code_vulnerabilities[{computed_with}]": output}

    return data


##########################################################################


# GET behavior analysis
@app.get("/api/report/{id}/behavior/")
async def get_behavior_analysis(id):
    data = prepare_behavior_analysis_output(id)

    return data


# GET threat analysis
@app.get("/api/report/{id}/behavior/threats/")
async def get_threats_analysis(id):
    output, computed_with = prepare_threat_analysis_output(id)
    data = {f"threats[{computed_with}]": output}

    return data


# GET permission analysis
@app.get("/api/report/{id}/behavior/permissions/")
async def get_permission_analysis(id):
    output, computed_with = prepare_permission_analysis_output(id)
    data = {f"permissions[{computed_with}]": output}

    return data


# GET detailed permission analysis
@app.get("/api/report/{id}/behavior/detailed-permissions/")
async def get_detailed_permissions(id):
    output, computed_with = prepare_detailed_permissions_analysis_output(id)
    data = {f"detailed_permissions[{computed_with}]": output}

    return data


##########################################################################


@app.get("/api/report/{id}/control-flow/")
async def get_control_flow(id):
    output = json.dumps({})
    return output


##########################################################################


# GET network analysis
@app.get("/api/report/{id}/network/")
async def get_network_analysis(id):
    data = prepare_network_analysis_output(id)

    return data


# GET domain analysis
@app.get("/api/report/{id}/network/domains/")
async def get_domain_analysis(id):
    output, computed_with = prepare_domain_analysis_output(id)
    data = {f"domains[{computed_with}]": output}

    return data


# GET URL analysis
@app.get("/api/report/{id}/network/urls/")
async def get_url_analysis(id):
    output, computed_with = prepare_url_analysis_output(id)
    data = {f"urls[{computed_with}]": output}

    return data
