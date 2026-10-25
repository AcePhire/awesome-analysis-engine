import sys
import gc
import json
import hashlib
from androguard.core.apk import APK
from androguard.misc import AnalyzeAPK
from androguard import util as AndroUtil
from google_play_scraper import app
from fingerprinting import ApplicationSignature
from datetime import datetime 

# Check that a path's average segment length is at least 2 characters
def _lcheck(name):
    name = str(name)
    count = name.count('/') + 1
    length = len(name)
    return length / count >= 2

# Return the SHA256 of a file
def get_sha256(path):
    with open(path, "rb") as f:
        sha256 = hashlib.sha256(f.read()).hexdigest()
    return sha256

# Compute the app signature and add manifest, SDK, permission, component and signing info
def extract_attributes(path):
    with open(path) as f:
        sign = ApplicationSignature.compute_from_apk(f.name)
        package = sign.handle

        sign = sign.to_dict()

        a = APK(f.name)
        sign['uploaded_at'] = datetime.now()
        sign['sha256'] = get_sha256(path)
        sign['activities'] = a.get_activities()
        sign['features'] = a.get_features()
        sign['libraries'] = a.get_libraries()
        sign['main_activity'] = a.get_main_activity()
        sign['min_sdk_version'] = a.get_min_sdk_version()
        sign['max_sdk_version'] = a.get_max_sdk_version()
        sign['target_sdk_version'] = a.get_target_sdk_version()
        sign['permissions'] = a.get_permissions()
        sign['aosp_permissions'] = a.get_requested_aosp_permissions()
        sign['third_party_permissions'] = a.get_requested_third_party_permissions()
        sign['providers'] = a.get_providers()
        sign['receivers'] = a.get_receivers()
        sign['services'] = a.get_services()
        sign['is_valid'] = a.is_valid_APK()
        sign['is_signed'] = a.is_signed()
        sign['is_signed_v1'] = a.is_signed_v1()
        sign['is_signed_v2'] = a.is_signed_v2()
        sign['is_signed_v3'] = a.is_signed_v3()

    del a, f
    gc.collect()

    return package, sign

# Detect Google Play frosting and list the APK signing block entries
def frosting_analysis(path):
    BLOCK_TYPES = {
        0x2146444e: 'Google metadata',
        0x42726577: 'Verity padding',
        0x6dff800d: 'Source stamp V2 X509 cert',
        0x71777777: 'Meituan metadata',
        0x504b4453: 'Dependency metadata',
    }

    with open(path) as f:
        try:
            a = APK(f.name)
            a.parse_v2_v3_signature()

            frosting_data = {
                "is_frosted": 0x2146444e in a._v2_blocks,
                "v2_signature_blocks": []
            }

            for b in a._v2_blocks:
                if b in BLOCK_TYPES.keys():
                    frosting_data['v2_signature_blocks'].append(
                        {
                            'value': str(hex(b)),
                            'comment': BLOCK_TYPES[b],
                            'content': binascii.b2a_base64(a._v2_blocks[b]).decode('utf-8').strip()
                        }
                    )
                else:
                    frosting_data['v2_signature_blocks'].append(
                        {
                            'value': str(hex(b)),
                            'comment': 'Unknown',
                            'content': binascii.b2a_base64(a._v2_blocks[b]).decode('utf-8').strip()
                        }
                    )

        except Exception as e:
            frosting_data = {
                "is_frosted": "N/A",
                "v2_signature_blocks": []
            }
    
    return frosting_data


# Return the app's class names, excluding Kotlin, Android and Java standard libraries
def extract_classes(path):
    with open(path) as f:
        a, d, dx = AnalyzeAPK(f.name)

        class_names = []
        try:
            for class_name in dx.classes:
                if not class_name.startswith("Lkotlin/") and not class_name.startswith(
                    "Landroid/") and not class_name.startswith("Landroidx/") and not class_name.startswith(
                    "Ljavax/") and not class_name.startswith("Lkotlinx/") and not class_name.startswith(
                    "Ljava/"):
                    class_names.append(str(class_name))
        except Exception as e:
            print(e)

    del a, d, dx, f
    gc.collect()
        
    return class_names

# Look up the package on Google Play alongside its extracted signature
def get_google_play_info(path):
    package, sign = extract_attributes(path)

    try:
        details = app(
            package,
            lang="en",
            country="us"
        )

        if details:
            print({
                "id": package,
                "sign": sign,
                "details": details
            })
            del details
            
    except Exception as e:
        return {
                "id": package,
                "sign": sign,
                "details": "no google play info"
        }
    finally:
        gc.collect()


if __name__ == "__main__":
    AndroUtil.set_log("CRITICAL")
    path = sys.argv[1]

    apk_info = {
        "frosting_info": frosting_analysis(path),
        "extracted_classes": extract_classes(path),
        "google_play_info": get_google_play_info(path)
    }

    print(json.dumps(apk_info, indent=2, default=str))
