rule MALWARE_SPARKRAT_GOLANG {
	meta:
		version = "1"
		date = "1/10/24"
		modified = "1/10/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "SparkRat Golang Function Names and regex for build ID"
		category = "malware"
		malware_type = "BACKDOOR"
		malware_family = "SPARKRAT"
		mitre_att = "TA0007, TA0011"
		actor_type = "APT, CRIMEWARE"
		actor = "N/A"
		report = "https://github.com/XZB-1248/Spark, https://asec.ahnlab.com/en/52899/, https://www.sentinelone.com/labs/dragonspark-attacks-evade-detection-with-sparkrat-and-golang-source-code-interpretation/"
		hash = "86048394d153f9d0c3f06aae980735ac05bc0cca99977f98e623a31a68318116"
		hash = "78df6bd0995bb4fc53f96fbed5c4e370b9669c214d5ece45b3a157e108ca5d35"
		hash = "5431094ccb79a89214ad1b63ae4acb711edacadce267650fbd922f452e688081"
	strings:
		$str1 = "Spark/client/core"
		$str2 = "Spark/client/common"
		$str3 = "Spark/client/config"
		$str4 = "Spark/client/service/file"
		$str5 = "Spark/client/service/desktop"
		$str6 = "Spark/client/service/process"
		$str7 = "Spark/client/service/terminal"
		$buildid = "go.buildid"
		$regexGoBuildId = /Go build ID: \"[a-zA-Z0-9\/_-]{40,120}\"/ ascii wide
    condition:
    	 (uint16(0) == 0x5a4d or uint32(0) == 0x464c457f) and ((#regexGoBuildId == 1 or #buildid == 1) and any of ($str*))
}


rule INFO_ANDROID_APK_FILE {
	meta:
		version = "1"
		date = "1/12/24"
		modified = "1/12/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Using header match and common strings in android APK files"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://blog.avast.com/avast-tracks-down-tempting-cedar-spyware"
		hash = "ba2266540f401354f8f013dd222eeef5"
		hash = "7702fb2793fdf02562381f935461317245b7d3cd"
		hash = "2807AB1A912FF0751D5B7C7584D3D38ACC5C46AFFE2F168EEAEE70358DC90006"
	strings:
		$and1 = "classes.dex" ascii
    $and2 = "AndroidManifest" ascii
	condition:
    	uint32be(0) == 0x504B0304 and all of them
}


rule INFO_ANDROID_DEX_FILE {
	meta:
		version = "1"
		date = "1/13/24"
		modified = "1/13/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "matching the magic header of an Android Dalvik executable (Dex) File"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://blog.avast.com/avast-tracks-down-tempting-cedar-spyware"
		hash = "80cb839529f3f94b9bd9b2e8e2e1adef"
		hash = "b65c320dc02cff4d8f1bd32c135c6f4760d7fd83"
		hash = "10d150c2c59207a9b70835d5e0f47be1ce3c75060c4e9cc00676a83efe00e036"
	condition:
    uint32(0) == 0x0a786564
}


