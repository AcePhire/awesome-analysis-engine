import asyncio
import json
import shutil
from typing import Annotated

from fastapi import FastAPI, File, Path, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.sse import EventSourceResponse, ServerSentEvent
from pydantic_core.core_schema import TaggedUnionSchema

from awesome_analysis_engine import analyze
from formatter import *
from mongodb_handler import (
    get_analysis_status,
    list_apk_analyses,
)

# from ssdeep_compare import hash_compare
from utils import hash_file

# Metadata for each tag group — this is what renders as the section
# headers/descriptions in Swagger UI (/docs) and ReDoc (/redoc).
tags_metadata = [
    {
        "name": "Reports",
        "description": "List all analysis reports for submitted APKs.",
    },
    {
        "name": "Analysis Report",
        "description": "Retrieve all the information about a specific sample.",
    },
    {
        "name": "Analyze",
        "description": "Submit an APK sample for analysis.",
    },
    {
        "name": "Fingerprints",
        "description": "Retrieve the file identity data for a specific sample: checksums, identifier tools, and fuzzy hashes used for similarity matching.",
    },
    {
        "name": "Threat Intelligence",
        "description": "Retrieve the external threat intel for a specific sample: submission timeline, YARA rule matches, antivirus engine detections, and third-party lookups.",
    },
    {
        "name": "App Info",
        "description": "Retrieve the static APK metadata extracted from the manifest and package for a specific sample: app details, signing certificate, manifest analysis, and declared components activities, receivers, services).",
    },
    {
        "name": "Code Analysis",
        "description": "Retrieve the static code-level analysis results for a specific sample, including NIAP compliance checks and detected code vulnerabilities.",
    },
    {
        "name": "Behavior Analysis",
        "description": "Retrieve the runtime/behavioral findings for a specific sample: detected threats, requested permissions, and detailed permission analysis.",
    },
    {
        "name": "Control Flow",
        "description": "Retrieve the control-flow graph data for a specific sample.",
    },
    {
        "name": "Network Analysis",
        "description": "Retrieve the network indicators for a specific sample: contacted domains and URLs.",
    },
]

################################################# API  #################################################

app = FastAPI(openapi_tags=tags_metadata)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def home():
    return FileResponse("upload.html")


@app.post(
    "/api/analyze/",
    summary="Submit an APK for analysis",
    description="Upload an APK file, computes its SHA-256 hash, and queues it for analysis. Return the SHA-256 hash of the APK file",
    tags=["Analyze"],
)
async def analyze_apk(
    file: Annotated[UploadFile, File(description="APK file to analyze")],
):
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


@app.get(
    "/api/reports/",
    summary="List all APK analyses",
    description="Return a list of all APK analysis reports that have been submitted and analyzed",
    tags=["Reports"],
)
async def get_reports():
    return list_apk_analyses()


# GET full Report
# @app.get("/api/report/{id}/", response_class=EventSourceResponse)
# async def get_report(id) -> AsyncIterable[ServerSentEvent]:
#     data = prepare_report_output(id)

#     while get_analysis_status(id) == "pending":
#         yield ServerSentEvent(raw_data=json.dumps(data))
#         await asyncio.sleep(5)
#     yield ServerSentEvent(raw_data=json.dumps(data))


@app.get(
    "/api/report/{id}/",
    summary="Get the full analysis report",
    description="Return the complete, aggregated analysis report (fingerprints, threat intelligence, app information, code analysis, behavior analysis, and network analysis)",
    tags=["Analysis Report"],
)
async def get_report(
    id: Annotated[
        str, Path(description="Analysis report ID (SHA256 checksum of the APK file)")
    ],
):
    data = prepare_report_output(id)

    return data


##########################################################################


@app.get(
    "/api/report/{id}/fingerprints/",
    summary="Get fingerprints data",
    description="Return all the fingerprints data (checksums, identifiers, fuzzy hashes)",
    tags=["Fingerprints"],
)
async def get_fingerprints(
    id: Annotated[
        str, Path(description="Analysis report ID (SHA256 checksum of the APK file)")
    ],
):
    data = prepare_fingerprints_output(id)

    return data


@app.get(
    "/api/report/{id}/fingerprints/checksums/",
    summary="Get file checksums",
    description="Return file checksums (e.g. MD5, SHA256) computed",
    tags=["Fingerprints"],
)
async def get_checksums(
    id: Annotated[
        str, Path(description="Analysis report ID (SHA256 checksum of the APK file)")
    ],
):
    output, computed_with = prepare_checksums_output(id)

    data = {f"checksums[{computed_with}]": output}

    return data


@app.get(
    "/api/report/{id}/fingerprints/identifiers/",
    summary="Get APK identifiers",
    description="Return packer/obfuscator/compiler identifiers",
    tags=["Fingerprints"],
)
async def get_identifiers(
    id: Annotated[
        str, Path(description="Analysis report ID (SHA256 checksum of the APK file)")
    ],
):
    output, computed_with = prepare_apkid_output(id)

    data = {f"identifiers[{computed_with}]": [output]}

    return data


@app.get(
    "/api/report/{id}/fingerprints/fuzzy-hashes/",
    summary="Get fuzzy hashes",
    description="Return fuzzy hash values (e.g. ssdeep) used for similarity comparisons",
    tags=["Fingerprints"],
)
async def get_fuzzy_hashes(
    id: Annotated[
        str, Path(description="Analysis report ID (SHA256 checksum of the APK file)")
    ],
):
    output, computed_with = prepare_fuzzy_hash_output(id)

    data = {f"fuzzy-hashes[{computed_with}]": output}

    return data


##########################################################################


@app.get(
    "/api/report/{id}/threat-intelligence/",
    summary="Get all threat intelligence data",
    description="Return all the threat intelligence data (sample timeline, YARA matches, antivirus detections, third-party lookups)",
    tags=["Threat Intelligence"],
)
async def get_threat_intelligence(
    id: Annotated[
        str, Path(description="Analysis report ID (SHA256 checksum of the APK file)")
    ],
):
    data = prepare_threat_intelligence_output(id)

    return data


@app.get(
    "/api/report/{id}/threat-intelligence/timeline/",
    summary="Get sample timeline",
    description="Return key dates for the sample (file creation, certficate validaity, first/last submission)",
    tags=["Threat Intelligence"],
)
async def get_sample_timeline(
    id: Annotated[
        str, Path(description="Analysis report ID (SHA256 checksum of the APK file)")
    ],
):
    output, computed_with = prepare_sample_timeline_output(id)
    data = {f"sample_timeline[{computed_with}]": output}

    return data


@app.get(
    "/api/report/{id}/threat-intelligence/yara/",
    summary="Get YARA rule matches",
    description="Return the YARA rule match results",
    tags=["Threat Intelligence"],
)
async def get_yara_analysis(
    id: Annotated[
        str, Path(description="Analysis report ID (SHA256 checksum of the APK file)")
    ],
):
    output, computed_with = prepare_yara_analysis_output(id)

    data = {f"yara_matches[{computed_with}]": output}

    return data


@app.get(
    "/api/report/{id}/threat-intelligence/av-detections/",
    summary="Get antivirus detections",
    description="Return the antivirus engine detections",
    tags=["Threat Intelligence"],
)
async def get_antivirus_detections(
    id: Annotated[
        str, Path(description="Analysis report ID (SHA256 checksum of the APK file)")
    ],
):
    data = {}
    json_data = json.dumps(data)

    return json_data


@app.get(
    "/api/report/{id}/threat-intelligence/third-party-apps/",
    summary="Get 3rd-party lookup results",
    description="Return lookup results for 3rd-party threat intelligence sources (e.g. VirusTotal, MalwareBazaar)",
    tags=["Threat Intelligence"],
)
async def get_third_party_apps(
    id: Annotated[
        str, Path(description="Analysis report ID (SHA256 checksum of the APK file)")
    ],
):
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


@app.get(
    "/api/report/{id}/app/",
    summary="Get all app information",
    description="Return the full app information (details, certificates, manifests, activities, receivers, services)",
    tags=["App Info"],
)
async def get_app_analysis(
    id: Annotated[
        str, Path(description="Analysis report ID (SHA256 checksum of the APK file)")
    ],
):
    data = prepare_apk_analysis_output(id)

    return data


@app.get(
    "/api/report/{id}/app/details/",
    summary="Get app details",
    description="Return basic app metadata (package name, version, size, etc. ",
    tags=["App Info"],
)
async def get_app_details(
    id: Annotated[
        str, Path(description="Analysis report ID (SHA256 checksum of the APK file)")
    ],
):
    output, computed_with = prepare_apk_details_output(id)
    data = {
        f"apk_details[{computed_with}]": output,
    }

    return data


@app.get(
    "/api/report/{id}/app/certificate/",
    summary="Get signing certificate details",
    description="Return the APK's signing certificate details (issuer, subject, validity, etc.)",
    tags=["App Info"],
)
async def get_app_certificate(
    id: Annotated[
        str, Path(description="Analysis report ID (SHA256 checksum of the APK file)")
    ],
):
    output, computed_with = prepare_certificate_details_output(id)
    data = {
        f"certificate_details[{computed_with}]": output,
    }

    return data


@app.get(
    "/api/report/{id}/app/manifests/",
    summary="Get app manifests",
    description="Return a list of manifests declared in the app's manifest files (AndroidManifest.xml, etc.)",
    tags=["App Info"],
)
async def get_app_manifests(
    id: Annotated[
        str, Path(description="Analysis report ID (SHA256 checksum of the APK file)")
    ],
):
    output, computed_with = prepare_manifest_analysis_output(id)
    data = {
        f"manifest_analysis[{computed_with}]": output,
    }

    return data


@app.get(
    "/api/report/{id}/app/activities/",
    summary="Get app activities",
    description="Return a list of activities declared in the app's manifest files (AndroidManifest.xml, etc. )",
    tags=["App Info"],
)
async def get_app_activities(
    id: Annotated[
        str, Path(description="Analysis report ID (SHA256 checksum of the APK file)")
    ],
):
    output, computed_with = prepare_activities_output(id)
    data = {
        f"activities[{computed_with}]": output,
    }

    return data


@app.get(
    "/api/report/{id}/app/receivers/",
    summary="Get app receivers",
    description="Return a list of receivers declared in the app's manifest files (AndroidManifest.xml, etc.)",
    tags=["App Info"],
)
async def get_app_receivers(
    id: Annotated[
        str, Path(description="Analysis report ID (SHA256 checksum of the APK file)")
    ],
):
    output, computed_with = prepare_receivers_output(id)
    data = {
        f"receivers[{computed_with}]": output,
    }

    return data


@app.get(
    "/api/report/{id}/app/services/",
    summary="Get app services",
    description="Return a list of services declared in the app's manifest files (AndroidManifest.xml, etc.)",
    tags=["App Info"],
)
async def get_app_services(
    id: Annotated[
        str, Path(description="Analysis report ID (SHA256 checksum of the APK file)")
    ],
):
    output, computed_with = prepare_services_output(id)
    data = {
        f"services[{computed_with}]": output,
    }

    return data


##########################################################################


@app.get(
    "/api/report/{id}/code/",
    summary="Get all code analysis results",
    description="Return the full code analysis results (NIAP compliance, vulnerabilities)",
    tags=["Code Analysis"],
)
async def get_code_analysis(
    id: Annotated[
        str, Path(description="Analysis report ID (SHA256 checksum of the APK file)")
    ],
):
    data = prepare_code_analysis_output(id)

    return data


@app.get(
    "/api/report/{id}/code/niap/",
    summary="Get NIAP analysis",
    description="Return the NIAP (National Information Assurance Program) compliance analysis results",
    tags=["Code Analysis"],
)
async def get_niap_analysis(
    id: Annotated[
        str, Path(description="Analysis report ID (SHA256 checksum of the APK file)")
    ],
):
    output, computed_with = prepare_niap_analysis_output(id)
    data = {f"niap_analysis[{computed_with}]": output}

    return data


@app.get(
    "/api/report/{id}/code/vulnerabilities/",
    summary="Get code vulnerabilities",
    description="Return a list of vulnerabilities detected via static analysis of the code",
    tags=["Code Analysis"],
)
async def get_code_vulnerabilities(
    id: Annotated[
        str, Path(description="Analysis report ID (SHA256 checksum of the APK file)")
    ],
):
    output, computed_with = prepare_code_vulnerabilities_output(id)
    data = {f"code_vulnerabilities[{computed_with}]": output}

    return data


##########################################################################


@app.get(
    "/api/report/{id}/behavior/",
    summary="Get all behavior analysis results",
    description="Return the full behavior analysis results (threats, permissions, detailed permissions)",
    tags=["Behavior Analysis"],
)
async def get_behavior_analysis(
    id: Annotated[
        str, Path(description="Analysis report ID (SHA256 checksum of the APK file)")
    ],
):
    data = prepare_behavior_analysis_output(id)

    return data


@app.get(
    "/api/report/{id}/behavior/threats/",
    summary="Get behavioral threats",
    description="Return a list of threats (crimes) detected",
    tags=["Behavior Analysis"],
)
async def get_threats_analysis(
    id: Annotated[
        str, Path(description="Analysis report ID (SHA256 checksum of the APK file)")
    ],
):
    output, computed_with = prepare_threat_analysis_output(id)
    data = {f"threats[{computed_with}]": output}

    return data


@app.get(
    "/api/report/{id}/behavior/permissions/",
    summary="Get permissions analysis",
    description="Return a list of permissions requested by the APK",
    tags=["Behavior Analysis"],
)
async def get_permission_analysis(
    id: Annotated[
        str, Path(description="Analysis report ID (SHA256 checksum of the APK file)")
    ],
):
    output, computed_with = prepare_permission_analysis_output(id)
    data = {f"permissions[{computed_with}]": output}

    return data


@app.get(
    "/api/report/{id}/behavior/detailed-permissions/",
    summary="Get detailed permission analysis",
    description="Return a list of detailed permissions requested by the APK",
    tags=["Behavior Analysis"],
)
async def get_detailed_permissions(
    id: Annotated[
        str, Path(description="Analysis report ID (SHA256 checksum of the APK file)")
    ],
):
    output, computed_with = prepare_detailed_permissions_analysis_output(id)
    data = {f"detailed_permissions[{computed_with}]": output}

    return data


##########################################################################


@app.get(
    "/api/report/{id}/control-flow/",
    summary="Get control-flow graph data",
    description="Return the control-flow graph visualization of the behavior of the APK",
    tags=["Control Flow"],
)
async def get_control_flow(
    id: Annotated[
        str, Path(description="Analysis report ID (SHA256 checksum of the APK file)")
    ],
):
    output = json.dumps({})
    return output


##########################################################################


@app.get(
    "/api/report/{id}/network/",
    summary="Get all network analysis",
    description="Return the network analysis results (domains and URLs)",
    tags=["Network Analysis"],
)
async def get_network_analysis(
    id: Annotated[
        str, Path(description="Analysis report ID (SHA256 checksum of the APK file)")
    ],
):
    data = prepare_network_analysis_output(id)

    return data


@app.get(
    "/api/report/{id}/network/domains/",
    summary="Get network domains",
    description="Return a list of network domains accessed",
    tags=["Network Analysis"],
)
async def get_domain_analysis(
    id: Annotated[
        str, Path(description="Analysis report ID (SHA256 checksum of the APK file)")
    ],
):
    output, computed_with = prepare_domain_analysis_output(id)
    data = {f"domains[{computed_with}]": output}

    return data


@app.get(
    "/api/report/{id}/network/urls/",
    summary="Get network URLs",
    description="Return a list of network URLs accessed",
    tags=["Network Analysis"],
)
async def get_url_analysis(
    id: Annotated[
        str, Path(description="Analysis report ID (SHA256 checksum of the APK file)")
    ],
):
    output, computed_with = prepare_url_analysis_output(id)
    data = {f"urls[{computed_with}]": output}

    return data
