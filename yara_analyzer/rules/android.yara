rule Android_Suspicious_SMS {
    meta:
        description = "Detects SMS-sending malware patterns"
        severity    = "high"
    strings:
        $api1 = "sendTextMessage" ascii
        $api2 = "SmsManager"     ascii
        $perm = "SEND_SMS"       ascii
    condition:
        2 of them
}

rule Android_Dynamic_Code_Loading {
    meta:
        description = "Detects dynamic DEX/code loading"
    strings:
        $s1 = "DexClassLoader"     ascii
        $s2 = "PathClassLoader"    ascii
        $s3 = "loadClass"          ascii
        $s4 = "dalvik/system/Dex"  ascii
    condition:
        2 of ($s*)
}

rule Android_Root_Detection_Bypass {
    meta:
        description = "Detects root detection bypass attempts"
    strings:
        $r1 = "su"              ascii
        $r2 = "/system/bin/su"  ascii
        $r3 = "RootBeer"        ascii
        $r4 = "isRooted"        ascii
    condition:
        2 of them
}

rule Android_Native_Lib_Suspicious {
    meta:
        description = "Detects suspicious native library loading"
    strings:
        $l1 = "System.loadLibrary" ascii
        $l2 = "Runtime.exec"       ascii
    condition:
        all of them
}
