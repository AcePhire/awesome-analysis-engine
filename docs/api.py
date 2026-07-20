from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field, RootModel

DataT = TypeVar("DataT")


class Envelope(BaseModel, Generic[DataT]):
    computed_with: list[str] | None = Field(
        default=None,
        description="Tool(s) used to compute this data",
        examples=[["mobsf"]],
    )
    data: DataT | None = Field(default=None, description="The computed result")

class VerdictResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "verdict": "Malicious",
                "severity": "Medium",
                "reason": "Continuous communication has been found between the sample and suspecious domains",
                "response": "Delete the sample immediately and hand the phone over to a forensics team for deep analysis",
            }
        }
    )

    verdict: str | None = Field(default=None, description="Final verdict of whether the sample is malicious or not?", examples=["Malicious"])
    severity: str | None = Field(default=None, description="How malicious is this sample?", examples=["Medium"])
    reason: str | None = Field(default=None, description="Why has this sample been categorized as such?", examples=["Continuous communication has been found between the sample and suspecious domains"])
    response: str | None = Field(default=None, description="What should the user do to respond to this sample?", examples=["Delete the sample immediately and hand the phone over to a forensics team for deep analysis"])

class VerdictSectionResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "verdict": {
                    "computed_with": ["fukhara"],
                    "data": {
                        "verdict": "Malicious",
                        "severity": "Medium",
                        "reason": "Continuous communication has been found between the sample and suspecious domains",
                        "response": "Delete the sample immediately and hand the phone over to a forensics team for deep analysis",
                    },
                }
            }
        }
    )

    verdict: Envelope[VerdictResponse] | None = Field(default=None)

################################################# FINGERPRINTS #################################################


class ChecksumResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "size": "55.67MB",
                "md5": "f5936822b4567731e11bd3b03ad2305b",
                "sha1": "c705b93bce7efeedb5036d7416a056a7a01e6bea",
                "sha256": "39ac2d9fe73cb2b4d16ae34bb27dce263c338f1c4e443213302bc3493e9de7eb",
            }
        }
    )

    size: str | None = Field(
        default=None, description="Size of the sample", examples=["55.67MB"]
    )
    md5: str | None = Field(
        default=None,
        description="MD5 hash of the sample",
        examples=["f5936822b4567731e11bd3b03ad2305b"],
    )
    sha1: str | None = Field(
        default=None,
        description="SHA1 hash of the sample",
        examples=["c705b93bce7efeedb5036d7416a056a7a01e6bea"],
    )
    sha256: str | None = Field(
        default=None,
        description="SHA256 hash of the sample",
        examples=["39ac2d9fe73cb2b4d16ae34bb27dce263c338f1c4e443213302bc3493e9de7eb"],
    )


class ChecksumSectionResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "checksums": {
                    "computed_with": ["mobsf"],
                    "data": {
                        "size": "55.67MB",
                        "md5": "f5936822b4567731e11bd3b03ad2305b",
                        "sha1": "c705b93bce7efeedb5036d7416a056a7a01e6bea",
                        "sha256": "39ac2d9fe73cb2b4d16ae34bb27dce263c338f1c4e443213302bc3493e9de7eb",
                    },
                }
            }
        }
    )

    checksums: Envelope[ChecksumResponse] | None = Field(default=None)


class APKiDMatches(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "manipulator": ["Resource Confusion"],
                "anti_debug": ["Debug.isDebuggerConnected() check"],
                "anti_vm": ["Build.HARDWARE check"],
                "compiler": ["r8"],
                "obfuscator": ["Alipay"],
                "protector": ["MSA SDK"],
            }
        }
    )

    manipulator: list[str] | None = Field(
        default=None,
        description="List of indicators of alteration techniques found by analysis",
        examples=["Resource Confusion"],
    )
    anti_debug: list[str] | None = Field(
        default=None,
        description="List of indicators of anti-debugging techniques found by analysis",
        examples=["Debug.isDebuggerConnected() check"],
    )
    anti_vm: list[str] | None = Field(
        default=None,
        description="List of indicators of anti-vm techniques found by analysis",
        examples=["Build.HARDWARE check"],
    )
    compiler: list[str] | None = Field(
        default=None, description="List of suspecious compilers found", examples=["r8"]
    )
    obfuscator: list[str] | None = Field(
        default=None, description="List of obfuscators found", examples=["Alipay"]
    )
    protector: list[str] | None = Field(
        default=None, description="List of protectors found", examples=["MSA SDK"]
    )


class APKiDFiles(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "filename": "classes.dex",
                "matches": {
                    "manipulator": ["Resource Confusion"],
                    "anti_debug": ["Debug.isDebuggerConnected() check"],
                    "anti_vm": ["Build.HARDWARE check"],
                    "compiler": ["r8"],
                    "obfuscator": ["Alipay"],
                    "protector": ["MSA SDK"],
                },
            }
        }
    )

    filename: str | None = Field(
        default=None,
        description="Filename of the analyzed file",
        examples=["classes.dex"],
    )
    matches: APKiDMatches | None = Field(
        default=None, description="Matches found in the analyzed file"
    )


class APKiDResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "apkid_version": "3.6.6",
                "files": [
                    {
                        "filename": "classes.dex",
                        "matches": {
                            "manipulator": ["Resource Confusion"],
                            "anti_debug": ["Debug.isDebuggerConnected() check"],
                            "anti_vm": ["Build.HARDWARE check"],
                            "compiler": ["r8"],
                            "obfuscator": ["Alipay"],
                            "protector": ["MSA SDK"],
                        },
                    }
                ],
                "rules_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            }
        }
    )

    apkid_version: str | None = Field(
        default=None, description="APKiD verion", examples=["3.6.6"]
    )
    files: list[APKiDFiles] | None = Field(default=None)
    rules_sha256: str | None = Field(
        default=None,
        description="SHA256 hash of the YARA rules used by APKiD",
        examples=["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
    )


class IdentifiersApkidResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "files": {
                    "apkid_version": "3.6.6",
                    "files": [
                        {
                            "filename": "classes.dex",
                            "matches": {"compiler": ["r8"]},
                        }
                    ],
                    "rules_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                }
            }
        }
    )

    files: APKiDResponse | str | dict | None = Field(
        default=None,
        description="Raw APKiD tool output",
        examples=["{}"],
    )


class IdentifiersResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "apkid": {
                    "files": {
                        "apkid_version": "3.6.6",
                        "files": [
                            {
                                "filename": "classes.dex",
                                "matches": {"compiler": ["r8"]},
                            }
                        ],
                        "rules_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    }
                }
            }
        }
    )

    apkid: IdentifiersApkidResponse | None = Field(
        default=None, description="Results from APKiD"
    )


class IdentifiersSectionResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "identifiers": {
                    "computed_with": ["apkid"],
                    "data": {
                        "apkid": {
                            "files": {
                                "apkid_version": "3.6.6",
                                "files": [
                                    {
                                        "filename": "classes.dex",
                                        "matches": {"compiler": ["r8"]},
                                    }
                                ],
                                "rules_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                            }
                        }
                    },
                }
            }
        }
    )

    identifiers: Envelope[IdentifiersResponse] | None = Field(default=None)


class SSDeepHashesResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "filename": "classes3.dex",
                "fuzzy_hash": "3072:NSOl/RUN4vpCP6MHF10ZFvTXwxbno966V++cGUMFTQT6nMWCPglv9QMj:8GRUOe1UFI+3jODoFD",
            }
        }
    )

    filename: str | None = Field(
        default=None,
        description="Filename of the hashed file",
        examples=["classes3.dex"],
    )
    fuzzy_hash: str | None = Field(
        default=None,
        description="Fuzzy hash of the file",
        examples=[
            "3072:NSOl/RUN4vpCP6MHF10ZFvTXwxbno966V++cGUMFTQT6nMWCPglv9QMj:8GRUOe1UFI+3jODoFD"
        ],
    )


class FuzzyHashesResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "ssdeep": [
                    {
                        "filename": "classes3.dex",
                        "fuzzy_hash": "3072:NSOl/RUN4vpCP6MHF10ZFvTXwxbno966V++cGUMFTQT6nMWCPglv9QMj:8GRUOe1UFI+3jODoFD",
                    }
                ]
            }
        }
    )

    ssdeep: list[SSDeepHashesResponse] | None = Field(
        default=None, description="SSDeep Fuzzy Hashes"
    )


class FuzzyHashesSectionResponse(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "fuzzy-hashes": {
                    "computed_with": ["ssdeep"],
                    "data": {
                        "ssdeep": [
                            {
                                "filename": "classes3.dex",
                                "fuzzy_hash": "3072:NSOl/RUN4vpCP6MHF10ZFvTXwxbno966V++cGUMFTQT6nMWCPglv9QMj:8GRUOe1UFI+3jODoFD",
                            }
                        ]
                    },
                }
            }
        },
    )

    fuzzy_hashes: Envelope[FuzzyHashesResponse] | None = Field(
        default=None, alias="fuzzy-hashes"
    )


class FingerprintsResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "checksums": {
                    "computed_with": ["mobsf"],
                    "data": {
                        "size": "55.67MB",
                        "md5": "f5936822b4567731e11bd3b03ad2305b",
                        "sha1": "c705b93bce7efeedb5036d7416a056a7a01e6bea",
                        "sha256": "39ac2d9fe73cb2b4d16ae34bb27dce263c338f1c4e443213302bc3493e9de7eb",
                    },
                },
                "identifiers": {
                    "computed_with": ["apkid"],
                    "data": {"apkid": {"files": "{}"}},
                },
                "fuzzy_hashes": {
                    "computed_with": ["ssdeep"],
                    "data": {
                        "ssdeep": [
                            {
                                "filename": "classes3.dex",
                                "fuzzy_hash": "3072:NSOl/RUN4vpCP6MHF10ZFvTXwxbno966V++cGUMFTQT6nMWCPglv9QMj:8GRUOe1UFI+3jODoFD",
                            }
                        ]
                    },
                },
            }
        }
    )

    checksums: Envelope[ChecksumResponse] | None = Field(default=None)
    identifiers: Envelope[IdentifiersResponse] | None = Field(default=None)
    fuzzy_hashes: Envelope[FuzzyHashesResponse] | None = Field(default=None)


################################################# THREAT INTELLIGENCE #################################################


class TimelineResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "oldest_file_found_in_apk": "2025-11-27 04:04:42",
                "certificate_valid_not_before": "2025-11-25 15:53:29",
                "latest_file_found_in_apk": "2025-11-27 04:04:48",
                "first_submission_on_vt": "2025-11-26 23:20:05",
                "last_submission_on_vt": "2026-06-23 01:07:16",
                "upload_on_fukhara": "2026-07-08 11:58:31.763690",
                "certificate_valid_not_after": "2125-11-01 15:53:29",
            }
        }
    )

    oldest_file_found_in_apk: str | None = Field(
        default=None,
        description="Datetime of the oldest file found inside the APK sample",
        examples=["2025-11-27 04:04:42"],
    )
    certificate_valid_not_before: str | None = Field(
        default=None,
        description="Datetime of the certificate creation",
        examples=["2025-11-25 15:53:29"],
    )
    latest_file_found_in_apk: str | None = Field(
        default=None,
        description="Datetime of the latest file found inside the APK sample",
        examples=["2025-11-27 04:04:48"],
    )
    first_submission_on_vt: str | None = Field(
        default=None,
        description="Datetime of the first submission on VirusTotal",
        examples=["2025-11-26 23:20:05"],
    )
    last_submission_on_vt: str | None = Field(
        default=None,
        description="Datetime of the latest submission on VirusTotal",
        examples=["2026-06-23 01:07:16"],
    )
    upload_on_fukhara: str | None = Field(
        default=None,
        description="Datetime of submission on Fukhara",
        examples=["2026-07-08 11:58:31.763690"],
    )
    certificate_valid_not_after: str | None = Field(
        default=None,
        description="Datetime of the certificate expiration",
        examples=["2125-11-01 15:53:29"],
    )


class TimelineSectionResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "sample_timeline": {
                    "computed_with": ["fukhara", "virustotal"],
                    "data": {
                        "oldest_file_found_in_apk": "2025-11-27 04:04:42",
                        "certificate_valid_not_before": "2025-11-25 15:53:29",
                        "latest_file_found_in_apk": "2025-11-27 04:04:48",
                        "first_submission_on_vt": "2025-11-26 23:20:05",
                        "last_submission_on_vt": "2026-06-23 01:07:16",
                        "upload_on_fukhara": "2026-07-08 11:58:31.763690",
                        "certificate_valid_not_after": "2125-11-01 15:53:29",
                    },
                }
            }
        }
    )

    sample_timeline: Envelope[TimelineResponse] | None = Field(default=None)

class YaraMatchResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "source": "classes.dex",
                "rules": [
                    "Android_Dynamic_Code_Loading",
                    "Android_Root_Detection_Bypass",
                ],
            }
        }
    )

    source: str | None = Field(
        default=None,
        description="File the YARA rule matched against",
        examples=["classes.dex"],
    )
    rules: list[str] | None = Field(
        default=None,
        description="YARA rule name(s) that matched",
        examples=[["Android_Dynamic_Code_Loading", "Android_Root_Detection_Bypass"]],
    )


class YaraMatchesResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "matches": [
                    {
                        "source": "classes.dex",
                        "rules": [
                            "Android_Dynamic_Code_Loading",
                            "Android_Root_Detection_Bypass",
                        ],
                    }
                ]
            }
        }
    )

    matches: list[YaraMatchResponse] | None = Field(
        default=None, description="List of YARA rule matches found for the sample"
    )


class YaraSectionResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "yara_matches": {
                    "computed_with": ["yara_analyzer"],
                    "data": {
                        "matches": [
                            {
                                "source": "classes.dex",
                                "rules": [
                                    "Android_Dynamic_Code_Loading",
                                    "Android_Root_Detection_Bypass",
                                ],
                            }
                        ]
                    },
                }
            }
        }
    )

    yara_matches: Envelope[YaraMatchesResponse] | None = Field(default=None)

class AVDetectionsResponse(RootModel[list[dict[str, int]] | dict | None]):
    model_config = ConfigDict(
        json_schema_extra={"example": [{"Avast": 12}]}
    )


class AVDetectionsSectionResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "popular_av_detections": {
                    "computed_with": ["virustotal"],
                    "data": [{"Avast": 12}],
                }
            }
        }
    )

    popular_av_detections: Envelope[AVDetectionsResponse] | None = Field(default=None)


class ThirdPartyResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "virustotal": "https://www.virustotal.com/api/v3/files/<sha256>",
                "malwarebazaar": "https://bazaar.abuse.ch/sample/<sha256>",
            }
        }
    )

    virustotal: str | None = Field(
        default=None,
        description="Link to the VirusTotal analysis report",
        examples=["https://www.virustotal.com/api/v3/files/<sha256>"],
    )
    malwarebazaar: str | None = Field(
        default=None,
        description="Link to the MalwareBazaar sample page",
        examples=["https://bazaar.abuse.ch/sample/<sha256>"],
    )


class ThirdPartySectionResponse(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "third-party-apps": {
                    "computed_with": ["virustotal", "malwarebazaar"],
                    "data": {
                        "virustotal": "https://www.virustotal.com/api/v3/files/<sha256>",
                        "malwarebazaar": "https://bazaar.abuse.ch/sample/<sha256>",
                    },
                }
            }
        },
    )

    third_party_apps: Envelope[ThirdPartyResponse] | None = Field(
        default=None, alias="third-party-apps"
    )


class ThreatIntelligenceResponse(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "sample_timeline": {
                    "computed_with": ["fukhara", "virustotal"],
                    "data": {
                        "oldest_file_found_in_apk": "2025-11-27 04:04:42",
                        "certificate_valid_not_before": "2025-11-25 15:53:29",
                        "latest_file_found_in_apk": "2025-11-27 04:04:48",
                        "first_submission_on_vt": "2025-11-26 23:20:05",
                        "last_submission_on_vt": "2026-06-23 01:07:16",
                        "upload_on_fukhara": "2026-07-08 11:58:31.763690",
                        "certificate_valid_not_after": "2125-11-01 15:53:29",
                    },
                },
                "yara_matches": {
                    "computed_with": ["yara_analyzer"],
                    "data": {
                        "matches": [
                            {
                                "source": "classes.dex",
                                "rules": [
                                    "Android_Dynamic_Code_Loading",
                                    "Android_Root_Detection_Bypass",
                                ],
                            }
                        ]
                    },
                },
                "av-detections": {
                    "computed_with": ["virustotal"],
                    "data": [{"Avast": 12}],
                },
                "third-party-apps": {
                    "computed_with": ["virustotal", "malwarebazaar"],
                    "data": {
                        "virustotal": "https://www.virustotal.com/api/v3/files/<sha256>",
                        "malwarebazaar": "https://bazaar.abuse.ch/sample/<sha256>",
                    },
                },
            }
        },
    )

    sample_timeline: Envelope[TimelineResponse] | None = Field(default=None)
    yara_matches: Envelope[YaraMatchesResponse] | None = Field(default=None)
    av_detections: Envelope[AVDetectionsResponse] | None = Field(
        default=None, alias="av-detections"
    )
    third_party_apps: Envelope[ThirdPartyResponse] | None = Field(
        default=None, alias="third-party-apps"
    )


################################################# APP INFO #################################################

class FrostingResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={"example": {"is_frosted": "N/A", "v2_signature_blocks": []}}
    )

    is_frosted: bool | str | None = Field(
        default=None, description="Is the APK frosted", examples=[True, "N/A"]
    )
    v2_signature_blocks: list | None = Field(
        default=None, description="Signature blocks in the APK"
    )


class APKDetailsResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "package": "com.google.android",
                "app_name": "Google",
                "version_name": "4.2.0",
                "version_code": 400000039,
                "sdk": "21 - None",
                "uaid": "58ef88f27b2b2c48519f804a4ff445e387cee78b",
                "signature": "",
                "frosting": {"is_frosted": "N/A", "v2_signature_blocks": []},
            }
        }
    )

    package: str | None = Field(
        default=None,
        description="Package name of the APK",
        examples=["com.google.android"],
    )
    app_name: str | None = Field(
        default=None, description="Application name of the APK", examples=["Google"]
    )
    version_name: str | None = Field(
        default=None, description="Version name of the APK", examples=["4.2.0"]
    )
    version_code: int | None = Field(
        default=None, description="Version code of the APK", examples=[400000039]
    )
    sdk: str | None = Field(
        default=None,
        description="Software Development Kit (SDK) used for the APK development",
        examples=["21 - None"],
    )
    uaid: str | None = Field(
        default=None,
        description="Unique Application Identifier (UAID) of the APK",
        examples=["58ef88f27b2b2c48519f804a4ff445e387cee78b"],
    )
    signature: str | None = Field(
        default=None, description="APK signature", examples=[""]
    )
    frosting: FrostingResponse | None = Field(
        default=None, description="Frosting information of the APK"
    )


class APKDetailsSectionResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "apk_details": {
                    "computed_with": ["mobsf", "apk_info"],
                    "data": {
                        "package": "com.google.android",
                        "app_name": "Google",
                        "version_name": "4.2.0",
                        "version_code": 400000039,
                        "sdk": "21 - None",
                        "uaid": "58ef88f27b2b2c48519f804a4ff445e387cee78b",
                        "signature": "",
                        "frosting": {"is_frosted": "N/A", "v2_signature_blocks": []},
                    },
                }
            }
        }
    )

    apk_details: Envelope[APKDetailsResponse] | None = Field(default=None)


class CertificateResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "md5": "9ddde935852443ac9ecc5e794f9917f0",
                "sha1": "a6ee6410327ed17751a3e4e7b7a03337d5c00611",
                "sha256": "b751f0afed43e56cab08e886d8b65a7a4da654d568e5313cfd056ec6a5b1e028",
                "issuer": "Common Name: XX：XX, Organizational Unit: XXXX, Organization: XXXX, Locality: XX, State/Province: XX, Country: XXX",
                "not_before": "2023-07-25T09:05:22+00:00",
                "not_after": "3021-11-25T09:05:22+00:00",
            }
        }
    )

    md5: str | None = Field(
        default=None,
        description="MD5 hash of the certificate",
        examples=["9ddde935852443ac9ecc5e794f9917f0"],
    )
    sha1: str | None = Field(
        default=None,
        description="SHA1 hash of the certificate",
        examples=["a6ee6410327ed17751a3e4e7b7a03337d5c00611"],
    )
    sha256: str | None = Field(
        default=None,
        description="SHA256 hash of the certificate",
        examples=["b751f0afed43e56cab08e886d8b65a7a4da654d568e5313cfd056ec6a5b1e028"],
    )
    issuer: str | None = Field(
        default=None,
        description="Issuer of the certificate",
        examples=[
            "Common Name: XX：XX, Organizational Unit: XXXX, Organization: XXXX, Locality: XX, State/Province: XX, Country: XXX"
        ],
    )
    not_before: str | None = Field(
        default=None,
        description="Creation date of the certificate",
        examples=["2023-07-25T09:05:22+00:00"],
    )
    not_after: str | None = Field(
        default=None,
        description="Expiration date of the certificate",
        examples=["3021-11-25T09:05:22+00:00"],
    )


class CertificateSectionResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "certificate_details": {
                    "computed_with": ["apk_info"],
                    "data": {
                        "md5": "9ddde935852443ac9ecc5e794f9917f0",
                        "sha1": "a6ee6410327ed17751a3e4e7b7a03337d5c00611",
                        "sha256": "b751f0afed43e56cab08e886d8b65a7a4da654d568e5313cfd056ec6a5b1e028",
                        "issuer": "Common Name: XX：XX, Organizational Unit: XXXX, Organization: XXXX, Locality: XX, State/Province: XX, Country: XXX",
                        "not_before": "2023-07-25T09:05:22+00:00",
                        "not_after": "3021-11-25T09:05:22+00:00",
                    },
                }
            }
        }
    )

    certificate_details: Envelope[CertificateResponse] | None = Field(default=None)


class ManifestResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "rule": "vulnerable_os_version",
                "title": "App can be installed on a vulnerable unpatched Android version 5.0-5.0.2, [minSdk=21",
                "severity": "high",
                "description": "This application can be installed on an older version of android that has multiple unfixed vulnerabilities",
                "name": "vulnerable_os_version",
                "component": ["5.0-5.0.2", "21"],
            }
        }
    )

    rule: str | None = Field(
        default=None, description="Manifest name", examples=["vulnerable_os_version"]
    )
    title: str | None = Field(
        default=None,
        description="Manifest title",
        examples=[
            "App can be installed on a vulnerable unpatched Android version 5.0-5.0.2, [minSdk=21"
        ],
    )
    severity: str | None = Field(
        default=None, description="Manifest threat severity", examples=["high"]
    )
    description: str | None = Field(
        default=None,
        description="Manifest description",
        examples=[
            "This application can be installed on an older version of android that has multiple unfixed vulnerabilities"
        ],
    )
    name: str | None = Field(
        default=None, description="Manifest name", examples=["vulnerable_os_version"]
    )
    component: list[str] | None = Field(
        default=None,
        description="Manifest components",
        examples=[["5.0-5.0.2", "21"]],
    )


class ManifestSectionResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "manifest_analysis": {
                    "computed_with": ["mobsf"],
                    "data": [
                        {
                            "rule": "vulnerable_os_version",
                            "title": "App can be installed on a vulnerable unpatched Android version 5.0-5.0.2, [minSdk=21",
                            "severity": "high",
                            "description": "This application can be installed on an older version of android that has multiple unfixed vulnerabilities",
                            "name": "vulnerable_os_version",
                            "component": ["5.0-5.0.2", "21"],
                        }
                    ],
                }
            }
        }
    )

    manifest_analysis: Envelope[list[ManifestResponse] | dict] | None = Field(
        default=None
    )


class ActivitiesResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "main_activity": "com.google.android",
                "all_activities": ["com.google.android", "com.chrome.android"],
            }
        }
    )

    main_activity: str | None = Field(
        default=None,
        description="Main activity used by the APK",
        examples=["com.google.android"],
    )
    all_activities: list[str] | None = Field(
        default=None,
        description="List of all activities used by the APK",
        examples=[["com.google.android", "com.chrome.android"]],
    )


class ActivitiesSectionResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "activities": {
                    "computed_with": ["mobsf"],
                    "data": {
                        "main_activity": "com.google.android",
                        "all_activities": [
                            "com.google.android",
                            "com.chrome.android",
                        ],
                    },
                }
            }
        }
    )

    activities: Envelope[ActivitiesResponse] | None = Field(default=None)


class ReceiversResponse(RootModel[list[str] | None]):
    model_config = ConfigDict(
        json_schema_extra={
            "example": [
                "com.google.android.commonlib.service.EnqueueService",
                "com.google.platform.oaidkit.OAIDLoadService",
            ]
        }
    )


class ReceiversSectionResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "receivers": {
                    "computed_with": ["mobsf"],
                    "data": [
                        "com.google.android.commonlib.service.EnqueueService",
                        "com.google.platform.oaidkit.OAIDLoadService",
                    ],
                }
            }
        }
    )

    receivers: Envelope[ReceiversResponse] | None = Field(default=None)


class ServicesResponse(RootModel[list[str] | None]):
    model_config = ConfigDict(
        json_schema_extra={
            "example": [
                "com.google.android.share.douyin.StayInDouyinReceiver",
                "com.google.myssdk.share.callback.MysShareCallbackReceiver",
            ]
        }
    )


class ServicesSectionResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "services": {
                    "computed_with": ["mobsf"],
                    "data": [
                        "com.google.android.share.douyin.StayInDouyinReceiver",
                        "com.google.myssdk.share.callback.MysShareCallbackReceiver",
                    ],
                }
            }
        }
    )

    services: Envelope[ServicesResponse] | None = Field(default=None)


class AppAnalysisResponse(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "apk_details": {
                    "computed_with": ["mobsf", "apk_info"],
                    "data": {
                        "package": "com.google.android",
                        "app_name": "Google",
                        "version_name": "4.2.0",
                        "version_code": 400000039,
                        "sdk": "21 - None",
                        "uaid": "58ef88f27b2b2c48519f804a4ff445e387cee78b",
                        "signature": "",
                        "frosting": {"is_frosted": "N/A", "v2_signature_blocks": []},
                    },
                },
                "certificate_details": {
                    "computed_with": ["apk_info"],
                    "data": {
                        "md5": "9ddde935852443ac9ecc5e794f9917f0",
                        "sha1": "a6ee6410327ed17751a3e4e7b7a03337d5c00611",
                        "sha256": "b751f0afed43e56cab08e886d8b65a7a4da654d568e5313cfd056ec6a5b1e028",
                        "issuer": "Common Name: XX：XX, Organizational Unit: XXXX, Organization: XXXX, Locality: XX, State/Province: XX, Country: XXX",
                        "not_before": "2023-07-25T09:05:22+00:00",
                        "not_after": "3021-11-25T09:05:22+00:00",
                    },
                },
                "manifest_analysis": {
                    "computed_with": ["mobsf"],
                    "data": [
                        {
                            "rule": "vulnerable_os_version",
                            "title": "App can be installed on a vulnerable unpatched Android version 5.0-5.0.2, [minSdk=21",
                            "severity": "high",
                            "description": "This application can be installed on an older version of android that has multiple unfixed vulnerabilities",
                            "name": "vulnerable_os_version",
                            "component": ["5.0-5.0.2", "21"],
                        }
                    ],
                },
                "acitivities": {
                    "computed_with": ["mobsf"],
                    "data": {
                        "main_activity": "com.google.android",
                        "all_activities": [
                            "com.google.android",
                            "com.chrome.android",
                        ],
                    },
                },
                "receivers": {
                    "computed_with": ["mobsf"],
                    "data": [
                        "com.google.android.commonlib.service.EnqueueService",
                        "com.google.platform.oaidkit.OAIDLoadService",
                    ],
                },
                "services": {
                    "computed_with": ["mobsf"],
                    "data": [
                        "com.google.android.share.douyin.StayInDouyinReceiver",
                        "com.google.myssdk.share.callback.MysShareCallbackReceiver",
                    ],
                },
            }
        },
    )

    apk_details: Envelope[APKDetailsResponse] | None = Field(default=None)
    certificate_details: Envelope[CertificateResponse] | None = Field(default=None)
    manifest_analysis: Envelope[list[ManifestResponse] | dict] | None = Field(
        default=None
    )
    activities: Envelope[ActivitiesResponse] | None = Field(
        default=None, alias="acitivities"
    )
    receivers: Envelope[ReceiversResponse] | None = Field(default=None)
    services: Envelope[ServicesResponse] | None = Field(default=None)


################################################# CODE ANALYSIS #################################################


class NiapAnalysisResponse(RootModel[dict | None]):
    model_config = ConfigDict(json_schema_extra={"example": {}})


class NiapSectionResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {"niap_analysis": {"computed_with": ["mobsf"], "data": {}}}
        }
    )

    niap_analysis: Envelope[NiapAnalysisResponse] | None = Field(default=None)


class CodeVulnerabilityMetadata(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "cvss": 7.5,
                "cwe": "CWE-532: Insertion of Sensitive Information into Log File",
                "owasp-mobile": "M2: Insecure Data Storage",
                "masvs": "MSTG-STORAGE-3",
                "ref": "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#logs",
                "description": "The App logs information. Sensitive information should never be logged.",
                "severity": "warning",
            }
        },
    )

    cvss: float | None = Field(
        default=None, description="CVSS score of the finding", examples=[7.5]
    )
    cwe: str | None = Field(
        default=None,
        description="CWE identifier and title",
        examples=["CWE-532: Insertion of Sensitive Information into Log File"],
    )
    owasp_mobile: str | None = Field(
        default=None,
        alias="owasp-mobile",
        description="OWASP Mobile Top 10 category",
        examples=["M2: Insecure Data Storage"],
    )
    masvs: str | None = Field(
        default=None,
        description="MASVS control ID",
        examples=["MSTG-STORAGE-3"],
    )
    ref: str | None = Field(
        default=None,
        description="Reference link for the finding",
        examples=[
            "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#logs"
        ],
    )
    description: str | None = Field(
        default=None, description="Description of the code finding"
    )
    severity: str | None = Field(
        default=None, description="Severity of the finding", examples=["warning"]
    )


class CodeVulnerabilityFinding(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "files": {"jakhar/aseem/diva/LogActivity.java": "24"},
                "metadata": {
                    "cvss": 7.5,
                    "cwe": "CWE-532: Insertion of Sensitive Information into Log File",
                    "owasp-mobile": "M2: Insecure Data Storage",
                    "masvs": "MSTG-STORAGE-3",
                    "ref": "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#logs",
                    "description": "The App logs information. Sensitive information should never be logged.",
                    "severity": "warning",
                },
            }
        }
    )

    files: dict[str, str] | None = Field(
        default=None,
        description="Map of source file path to matching line number(s), comma-separated",
        examples=[{"jakhar/aseem/diva/LogActivity.java": "24"}],
    )
    metadata: CodeVulnerabilityMetadata | None = Field(default=None)


class CodeVulnerabilitiesResponse(
    RootModel[dict[str, CodeVulnerabilityFinding] | None]
):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "android_logging": {
                    "files": {"jakhar/aseem/diva/LogActivity.java": "24"},
                    "metadata": {
                        "cvss": 7.5,
                        "cwe": "CWE-532: Insertion of Sensitive Information into Log File",
                        "owasp-mobile": "M2: Insecure Data Storage",
                        "masvs": "MSTG-STORAGE-3",
                        "ref": "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#logs",
                        "description": "The App logs information. Sensitive information should never be logged.",
                        "severity": "warning",
                    },
                }
            }
        }
    )


class CodeVulnerabilitiesSectionResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "code_vulnerabilities": {
                    "computed_with": ["mobsf"],
                    "data": {
                        "android_logging": {
                            "files": {"jakhar/aseem/diva/LogActivity.java": "24"},
                            "metadata": {
                                "cvss": 7.5,
                                "cwe": "CWE-532: Insertion of Sensitive Information into Log File",
                                "owasp-mobile": "M2: Insecure Data Storage",
                                "masvs": "MSTG-STORAGE-3",
                                "ref": "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#logs",
                                "description": "The App logs information. Sensitive information should never be logged.",
                                "severity": "warning",
                            },
                        }
                    },
                }
            }
        }
    )

    code_vulnerabilities: Envelope[CodeVulnerabilitiesResponse] | None = Field(
        default=None
    )


class CodeAnalysisResponse(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "niap_analysis": {"computed_with": ["mobsf"], "data": {}},
                "code_vulnerabilties": {
                    "computed_with": ["mobsf"],
                    "data": {
                        "android_logging": {
                            "files": {"jakhar/aseem/diva/LogActivity.java": "24"},
                            "metadata": {
                                "cvss": 7.5,
                                "cwe": "CWE-532: Insertion of Sensitive Information into Log File",
                                "owasp-mobile": "M2: Insecure Data Storage",
                                "masvs": "MSTG-STORAGE-3",
                                "ref": "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#logs",
                                "description": "The App logs information. Sensitive information should never be logged.",
                                "severity": "warning",
                            },
                        }
                    },
                },
            }
        },
    )

    niap_analysis: Envelope[NiapAnalysisResponse] | None = Field(default=None)
    code_vulnerabilities: Envelope[CodeVulnerabilitiesResponse] | None = Field(
        default=None, alias="code_vulnerabilties"
    )


################################################# BEHAVIOR ANALYSIS #################################################


class ThreatResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {"crime": "Read Sensitive Data", "confidence": "80%"}
        }
    )

    crime: str | None = Field(
        default=None,
        description="Detected behavioral crime/capability",
        examples=["Read Sensitive Data"],
    )
    confidence: str | None = Field(
        default=None,
        description="Confidence level of the detection",
        examples=["80%"],
    )


class ThreatsSectionResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "threats": {
                    "computed_with": ["quark_engine"],
                    "data": [{"crime": "Read Sensitive Data", "confidence": "80%"}],
                }
            }
        }
    )

    threats: Envelope[list[ThreatResponse]] | None = Field(default=None)

class PermissionInfo(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "status": "dangerous",
                "info": "display system-level alerts",
                "description": "Allows an application to show system-alert windows. Malicious applications can take over the entire screen of the phone.",
            }
        }
    )

    status: str | None = Field(
        default=None,
        description="MobSF risk classification for the permission",
        examples=["dangerous"],
    )
    info: str | None = Field(
        default=None,
        description="Short label for what the permission grants",
        examples=["read external storage contents"],
    )
    description: str | None = Field(
        default=None,
        description="Full description of what the permission allows",
        examples=["Allows an application to read from external storage."],
    )



class PermissionsResponse(RootModel[dict[str, PermissionInfo] | None]):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "android.permission.SYSTEM_ALERT_WINDOW": {
                    "status": "dangerous",
                    "info": "display system-level alerts",
                    "description": "Allows an application to show system-alert windows. Malicious applications can take over the entire screen of the phone.",
                }
            }
        }
    )

class PermissionsSectionResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "permissions": {
                    "computed_with": ["mobsf"],
                    "data": {
                        "android.permission.SYSTEM_ALERT_WINDOW": {
                            "status": "dangerous",
                            "info": "display system-level alerts",
                            "description": "Allows an application to show system-alert windows. Malicious applications can take over the entire screen of the phone.",
                        }
                    },
                }
            }
        }
    )

    permissions: Envelope[PermissionsResponse] | None = Field(default=None)

class ApiUsageMetadata(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "description": "Local File I/O Operations",
                "severity": "info",
            }
        }
    )

    description: str | None = Field(
        default=None, description="Description of the API usage category"
    )
    severity: str | None = Field(
        default=None, description="Severity of the usage", examples=["info"]
    )


class ApiUsageFinding(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "files": {"jakhar/aseem/diva/MainActivity.java": "40,45,50"},
                "metadata": {
                    "description": "Local File I/O Operations",
                    "severity": "info",
                },
            }
        }
    )

    files: dict[str, str] | None = Field(
        default=None,
        description="Map of source file path to matching line number(s), comma-separated",
        examples=[{"jakhar/aseem/diva/MainActivity.java": "40,45,50"}],
    )
    metadata: ApiUsageMetadata | None = Field(default=None)


class DetailedPermissionsResponse(RootModel[dict[str, ApiUsageFinding] | None]):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "api_local_file_io": {
                    "files": {"jakhar/aseem/diva/MainActivity.java": "40,45,50"},
                    "metadata": {
                        "description": "Local File I/O Operations",
                        "severity": "info",
                    },
                }
            }
        }
    )


class DetailedPermissionsSectionResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "detailed_permissions": {
                    "computed_with": ["mobsf"],
                    "data": {
                        "api_local_file_io": {
                            "files": {
                                "jakhar/aseem/diva/MainActivity.java": "40,45,50"
                            },
                            "metadata": {
                                "description": "Local File I/O Operations",
                                "severity": "info",
                            },
                        }
                    },
                }
            }
        }
    )

    detailed_permissions: Envelope[DetailedPermissionsResponse] | None = Field(
        default=None
    )


class BehaviorAnalysisResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "threats": {
                    "computed_with": ["quark_engine"],
                    "data": [{"crime": "Read Sensitive Data", "confidence": "80%"}],
                },
                "permissions": {
                    "computed_with": ["mobsf"],
                    "data": {
                        "android.permission.SYSTEM_ALERT_WINDOW": {
                            "status": "dangerous",
                            "info": "display system-level alerts",
                            "description": "Allows an application to show system-alert windows. Malicious applications can take over the entire screen of the phone.",
                        }
                    },
                },
                "detailed_permissions": {
                    "computed_with": ["mobsf"],
                    "data": {
                        "api_local_file_io": {
                            "files": {
                                "jakhar/aseem/diva/MainActivity.java": "40,45,50"
                            },
                            "metadata": {
                                "description": "Local File I/O Operations",
                                "severity": "info",
                            },
                        }
                    },
                },
            }
        }
    )

    threats: Envelope[list[ThreatResponse]] | None = Field(default=None)
    permissions: Envelope[PermissionsResponse] | None = Field(default=None)
    detailed_permissions: Envelope[DetailedPermissionsResponse] | None = Field(
        default=None
    )


################################################# NETWORK ANALYSIS #################################################


class GeolocationResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "ip": "172.67.72.183",
                "country_short": "US",
                "country_long": "United States of America",
                "region": "California",
                "city": "San Francisco",
                "latitude": "37.775700",
                "longitude": "-122.395203",
            }
        }
    )

    ip: str | None = Field(default=None, examples=["172.67.72.183"])
    country_short: str | None = Field(default=None, examples=["US"])
    country_long: str | None = Field(
        default=None, examples=["United States of America"]
    )
    region: str | None = Field(default=None, examples=["California"])
    city: str | None = Field(default=None, examples=["San Francisco"])
    latitude: str | None = Field(default=None, examples=["37.775700"])
    longitude: str | None = Field(default=None, examples=["-122.395203"])


class DomainInfoResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "bad": "no",
                "geolocation": {
                    "ip": "172.67.72.183",
                    "country_short": "US",
                    "country_long": "United States of America",
                    "region": "California",
                    "city": "San Francisco",
                    "latitude": "37.775700",
                    "longitude": "-122.395203",
                },
                "ofac": False,
            }
        }
    )

    bad: str | None = Field(
        default=None,
        description="Whether the domain is flagged as malicious",
        examples=["no"],
    )
    geolocation: GeolocationResponse | None = Field(default=None)
    ofac: bool | None = Field(
        default=None,
        description="Whether the domain appears on the OFAC sanctions list",
    )


class DomainsResponse(RootModel[dict[str, DomainInfoResponse] | None]):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "payatu.com": {
                    "bad": "no",
                    "geolocation": {
                        "ip": "172.67.72.183",
                        "country_short": "US",
                        "country_long": "United States of America",
                        "region": "California",
                        "city": "San Francisco",
                        "latitude": "37.775700",
                        "longitude": "-122.395203",
                    },
                    "ofac": False,
                }
            }
        }
    )


class DomainsSectionResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "domains": {
                    "computed_with": ["mobsf"],
                    "data": {
                        "payatu.com": {
                            "bad": "no",
                            "geolocation": {
                                "ip": "172.67.72.183",
                                "country_short": "US",
                                "country_long": "United States of America",
                                "region": "California",
                                "city": "San Francisco",
                                "latitude": "37.775700",
                                "longitude": "-122.395203",
                            },
                            "ofac": False,
                        }
                    },
                }
            }
        }
    )

    domains: Envelope[DomainsResponse] | None = Field(default=None)


class UrlEntryResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "urls": ["http://payatu.com"],
                "path": "jakhar/aseem/diva/APICreds2Activity.java",
            }
        }
    )

    urls: list[str] | None = Field(
        default=None,
        description="URL(s) found at this location",
        examples=[["http://payatu.com"]],
    )
    path: str | None = Field(
        default=None,
        description="Source file where the URL(s) were found",
        examples=["jakhar/aseem/diva/APICreds2Activity.java"],
    )


class UrlsResponse(RootModel[list[UrlEntryResponse] | None]):
    model_config = ConfigDict(
        json_schema_extra={
            "example": [
                {
                    "urls": ["http://payatu.com"],
                    "path": "jakhar/aseem/diva/APICreds2Activity.java",
                }
            ]
        }
    )


class UrlsSectionResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "urls": {
                    "computed_with": ["mobsf"],
                    "data": [
                        {
                            "urls": ["http://payatu.com"],
                            "path": "jakhar/aseem/diva/APICreds2Activity.java",
                        }
                    ],
                }
            }
        }
    )

    urls: Envelope[UrlsResponse] | None = Field(default=None)


class NetworkAnalysisResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "domains": {
                    "computed_with": ["mobsf"],
                    "data": {
                        "payatu.com": {
                            "bad": "no",
                            "geolocation": {
                                "ip": "172.67.72.183",
                                "country_short": "US",
                                "country_long": "United States of America",
                                "region": "California",
                                "city": "San Francisco",
                                "latitude": "37.775700",
                                "longitude": "-122.395203",
                            },
                            "ofac": False,
                        }
                    },
                },
                "urls": {
                    "computed_with": ["mobsf"],
                    "data": [
                        {
                            "urls": ["http://payatu.com"],
                            "path": "jakhar/aseem/diva/APICreds2Activity.java",
                        }
                    ],
                },
            }
        }
    )

    domains: Envelope[DomainsResponse] | None = Field(default=None)
    urls: Envelope[UrlsResponse] | None = Field(default=None)


################################################# FULL REPORT #################################################


class ReportResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "fingerprints": {
                    "checksums": {
                        "computed_with": ["mobsf"],
                        "data": {
                            "size": "55.67MB",
                            "md5": "f5936822b4567731e11bd3b03ad2305b",
                            "sha1": "c705b93bce7efeedb5036d7416a056a7a01e6bea",
                            "sha256": "39ac2d9fe73cb2b4d16ae34bb27dce263c338f1c4e443213302bc3493e9de7eb",
                        },
                    },
                    "identifiers": {
                        "computed_with": ["apkid"],
                        "data": {"apkid": {"files": "{}"}},
                    },
                    "fuzzy_hashes": {
                        "computed_with": ["ssdeep"],
                        "data": {
                            "ssdeep": [
                                {
                                    "filename": "classes3.dex",
                                    "fuzzy_hash": "3072:NSOl/RUN4vpCP6MHF10ZFvTXwxbno966V++cGUMFTQT6nMWCPglv9QMj:8GRUOe1UFI+3jODoFD",
                                }
                            ]
                        },
                    },
                },
                "threat_intelligence": {
                    "sample_timeline": {
                        "computed_with": ["fukhara", "virustotal"],
                        "data": {
                            "oldest_file_found_in_apk": "2025-11-27 04:04:42",
                            "certificate_valid_not_before": "2025-11-25 15:53:29",
                            "latest_file_found_in_apk": "2025-11-27 04:04:48",
                            "first_submission_on_vt": "2025-11-26 23:20:05",
                            "last_submission_on_vt": "2026-06-23 01:07:16",
                            "upload_on_fukhara": "2026-07-08 11:58:31.763690",
                            "certificate_valid_not_after": "2125-11-01 15:53:29",
                        },
                    },
                    "yara_matches": {
                        "computed_with": ["yara_analyzer"],
                        "data": {
                            "matches": [
                                {
                                    "source": "classes.dex",
                                    "rules": [
                                        "Android_Dynamic_Code_Loading",
                                        "Android_Root_Detection_Bypass",
                                    ],
                                }
                            ]
                        },
                    },
                    "av-detections": {
                        "computed_with": ["virustotal"],
                        "data": [{"Avast": 12}],
                    },
                    "third-party-apps": {
                        "computed_with": ["virustotal", "malwarebazaar"],
                        "data": {
                            "virustotal": "https://www.virustotal.com/api/v3/files/<sha256>",
                            "malwarebazaar": "https://bazaar.abuse.ch/sample/<sha256>",
                        },
                    },
                },
                "apk_analysis": {
                    "apk_details": {
                        "computed_with": ["mobsf", "apk_info"],
                        "data": {
                            "package": "com.google.android",
                            "app_name": "Google",
                            "version_name": "4.2.0",
                            "version_code": 400000039,
                            "sdk": "21 - None",
                            "uaid": "58ef88f27b2b2c48519f804a4ff445e387cee78b",
                            "signature": "",
                            "frosting": {
                                "is_frosted": "N/A",
                                "v2_signature_blocks": [],
                            },
                        },
                    },
                    "certificate_details": {
                        "computed_with": ["apk_info"],
                        "data": {
                            "md5": "9ddde935852443ac9ecc5e794f9917f0",
                            "sha1": "a6ee6410327ed17751a3e4e7b7a03337d5c00611",
                            "sha256": "b751f0afed43e56cab08e886d8b65a7a4da654d568e5313cfd056ec6a5b1e028",
                            "issuer": "Common Name: XX：XX, Organizational Unit: XXXX, Organization: XXXX, Locality: XX, State/Province: XX, Country: XXX",
                            "not_before": "2023-07-25T09:05:22+00:00",
                            "not_after": "3021-11-25T09:05:22+00:00",
                        },
                    },
                    "manifest_analysis": {
                        "computed_with": ["mobsf"],
                        "data": [
                            {
                                "rule": "vulnerable_os_version",
                                "title": "App can be installed on a vulnerable unpatched Android version 5.0-5.0.2, [minSdk=21",
                                "severity": "high",
                                "description": "This application can be installed on an older version of android that has multiple unfixed vulnerabilities",
                                "name": "vulnerable_os_version",
                                "component": ["5.0-5.0.2", "21"],
                            }
                        ],
                    },
                    "acitivities": {
                        "computed_with": ["mobsf"],
                        "data": {
                            "main_activity": "com.google.android",
                            "all_activities": [
                                "com.google.android",
                                "com.chrome.android",
                            ],
                        },
                    },
                    "receivers": {
                        "computed_with": ["mobsf"],
                        "data": [
                            "com.google.android.commonlib.service.EnqueueService",
                            "com.google.platform.oaidkit.OAIDLoadService",
                        ],
                    },
                    "services": {
                        "computed_with": ["mobsf"],
                        "data": [
                            "com.google.android.share.douyin.StayInDouyinReceiver",
                            "com.google.myssdk.share.callback.MysShareCallbackReceiver",
                        ],
                    },
                },
                "code_analysis": {
                    "niap_analysis": {"computed_with": ["mobsf"], "data": {}},
                    "code_vulnerabilties": {
                        "computed_with": ["mobsf"],
                        "data": {
                            "android_logging": {
                                "files": {
                                    "jakhar/aseem/diva/LogActivity.java": "24"
                                },
                                "metadata": {
                                    "cvss": 7.5,
                                    "cwe": "CWE-532: Insertion of Sensitive Information into Log File",
                                    "owasp-mobile": "M2: Insecure Data Storage",
                                    "masvs": "MSTG-STORAGE-3",
                                    "ref": "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#logs",
                                    "description": "The App logs information. Sensitive information should never be logged.",
                                    "severity": "warning",
                                },
                            }
                        },
                    },
                },
                "behavior_analysis": {
                    "threats": {
                        "computed_with": ["quark_engine"],
                        "data": [
                            {"crime": "Read Sensitive Data", "confidence": "80%"}
                        ],
                    },
                    "permissions": {
                        "computed_with": ["mobsf"],
                        "data": {
                            "android.permission.SYSTEM_ALERT_WINDOW": {
                                "status": "dangerous",
                                "info": "display system-level alerts",
                                "description": "Allows an application to show system-alert windows. Malicious applications can take over the entire screen of the phone.",
                            }
                        },
                    },
                    "detailed_permissions": {
                        "computed_with": ["mobsf"],
                        "data": {
                            "api_local_file_io": {
                                "files": {
                                    "jakhar/aseem/diva/MainActivity.java": "40,45,50"
                                },
                                "metadata": {
                                    "description": "Local File I/O Operations",
                                    "severity": "info",
                                },
                            }
                        },
                    },
                },
                "network_analysis": {
                    "domains": {
                        "computed_with": ["mobsf"],
                        "data": {
                            "payatu.com": {
                                "bad": "no",
                                "geolocation": {
                                    "ip": "172.67.72.183",
                                    "country_short": "US",
                                    "country_long": "United States of America",
                                    "region": "California",
                                    "city": "San Francisco",
                                    "latitude": "37.775700",
                                    "longitude": "-122.395203",
                                },
                                "ofac": False,
                            }
                        },
                    },
                    "urls": {
                        "computed_with": ["mobsf"],
                        "data": [
                            {
                                "urls": ["http://payatu.com"],
                                "path": "jakhar/aseem/diva/APICreds2Activity.java",
                            }
                        ],
                    },
                },
            }
        }
    )

    fingerprints: FingerprintsResponse | None = Field(default=None)
    threat_intelligence: ThreatIntelligenceResponse | None = Field(default=None)
    apk_analysis: AppAnalysisResponse | None = Field(default=None)
    code_analysis: CodeAnalysisResponse | None = Field(default=None)
    behavior_analysis: BehaviorAnalysisResponse | None = Field(default=None)
    network_analysis: NetworkAnalysisResponse | None = Field(default=None)


################################################# MISC #################################################


class AnalyzeResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "status": "success",
                "id": "39ac2d9fe73cb2b4d16ae34bb27dce263c338f1c4e443213302bc3493e9de7eb",
            }
        }
    )

    status: str | None = Field(default=None, examples=["success"])
    id: str | None = Field(
        default=None,
        description="SHA-256 hash of the submitted APK, used as the analysis report ID",
        examples=["39ac2d9fe73cb2b4d16ae34bb27dce263c338f1c4e443213302bc3493e9de7eb"],
    )
