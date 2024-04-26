import "pe"
//import "vt"

rule APT_CN_FISHMASTER_STRING_PDB_MALWARE {
	meta:
		version = "1"
		date = "1/26/24"
		modified = "1/26/24"
		status = "DEVELOPMENT"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Unique String and PDB path, using VT module to detect AV detection of Avast BidenHappy "
		category = "malware"
		malware_type = "BACKDOOR"
		malware_family = "FISHMASTER"
		mitre_att = "TA0002, TA0005, TA0007, TA0011"
		actor_type = "APT"
		actor = "WINNTI"
		report = "https://services.global.ntt/-/media/ntt/global/insights/white-papers/the-operations-of-winnti-group.pdf"
		report = "https://decoded.avast.io/luigicamastra/backdoored-client-from-mongolian-ca-monpass/"
        hash = "abcd461bdb6a6537b7a36848a87b5ea6"
		hash = "e99d5a620a488133f4da24e1f8d2d5e68542b6f3"
		hash = "f21a9c69bfca6f0633ba1e669e5cf86bd8fc55b2529cd9b064ff9e2e129525e8"
	strings:
        $str1 = "Bidenhappyhappyhappy"
        $pdb1 = "C:\\User\\test\\Desktop\\fishmaster\\x64\\Release\\fishmaster.pdb"
        $pdb2 = "\\fishmaster\\"
        $pdb3 = "\\fishmaster.pdb"
    condition:
		uint16(0) == 0x5a4d and
        ($str1 or (any of ($pdb*))) or pe.pdb_path == "C:\\Users\\test\\Desktop\\fishmaster\\x64\\Release\\fishmaster.pdb"
}

rule APT_CN_STATELYTAURUS_UNIQUE_STRINGS {
	meta:
		version = "1"
		date = "2/2/24"
		modified = "2/2/24"
		status = "DEVELOPMENT"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Unique Strings from blogpost"
		category = "malware"
		malware_type = "BACKDOOR"
		malware_family = "VARIES"
		mitre_att = "TA0002, TA0003, TA0004, TA0005, TA0006, TA0007, TA0009, TA0011"
		actor_type = "APT"
		actor = "Stately Taurus, Bronze President, Camaro Dragon, Earth Preta, Mustang Panda, Red Delta, TEMP.Hex, Luminous Moth"
		report = "https://csirt-cti.net/2024/02/01/stately-taurus-continued-new-information-on-cyberespionage-attacks-against-myanmar-military-junta/"
		hash = "b300afb993b501aca5b727b1c964810345cfa5b032f5774251a2570a3ae16995"
		hash = "6811e4b244a0f5c9fac6f8c135fcfff48940e89a33a5b21a552601c2bceb4614"
		hash = "6c90df591f638134db3b48ff1fd7111c366ec069c69ae28ee60d5cdd36408c02"
	strings:
		$STR1 = "14b0a22e33df6fab9"
		$STR2 = "243503098e6d85bd3367b2e25e144954e88d9a0b"
		$STR3 = "n9243503098e6d85bd3367b2e25e144954e88d9a0b"
		$STR4 = "bd3367b2e25e144954e88d9a0b3503098e6d85bd3367b2e25e"
		$STR5 = "144954e88d9a0b"
		$STR6 = "JeffreyEpsteindocumentsunsealed"
		$STR7 = "ChrisSanders"
	condition:
		any of them
}


import "pe"

rule APT_CN_TA410_REVOKED_CERTIFICATE {
	meta:
		version = "1"
		date = "1/27/24"
		modified = "1/27/24"
		status = "DEVELOPMENT"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Revoked Certificate Used to sign QuasarRAT"
		category = "malware"
		malware_type = "BACKDOOR"
		malware_family = "QuasarRAT"
		mitre_att = "TA0004, TA0005, TA0007, TA0009, TA0011"
		actor_type = "APT"
		actor = "TA410"
		report = "https://www.welivesecurity.com/2022/04/27/lookback-ta410-umbrella-cyberespionage-ttps-activity/"
		hash = "a7f147bec8b27c3f7183fb23dd17e444"
		hash = "5379fbb0e02694c524463fdf7f267a7361ecdd68"
		hash = "06eb951a9c5d3ce99182d535c5d714cc4e1aae53ef9fe51838189b41fc08380b"
	condition:
		uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_signatures) : (pe.signatures[i].serial == "4e:d8:73:0f:4e:1b:85:58:cd:1c:b0:10:7b:5f:77:6b")
}


import "pe"
rule APT_IR_NOJUSTICE_MALWARE_WIPER {
	meta:
		version = "1"
		date = "1/7/24"
		modified = "1/7/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "unique PDB Path or import hash for No Justice Wiper"
		category = "malware"
		malware_type = "WIPER"
		malware_family = "NoJustice"
		mitre_att = "T1561"
		actor_type = "APT"
		actor = "Homeland Justice"
		report = "https://www.clearskysec.com/wp-content/uploads/2024/01/No-Justice-Wiper.pdf"
		hash = "f9431cf3abcc85da8431f5480ee68f08"
		hash = "720c467046514f7376473b11271ebcb8d0a7e439"
		hash = "36cc72c55f572fe02836f25516d18fed1de768e7f29af7bdf469b52a3fe2531f"
	strings:
		$pdb1 = "\\LowEraser\\"
		$pdb2 = ":\\LowEraser\\LowEraser\\"
		$pdb3 = "\\LowEraser\\Release\\"
	condition:
		uint16(0) == 0x5a4d 
		and (pe.pdb_path == "F:\\LowEraser\\LowEraser\\Release\\Ptable.pdb" or (any of ($pdb*)))
		or (pe.imphash() == "6b09fb33bfe9c9cb20cb08d2f1aadb89")
}


import "pe"
rule APT_NK_KIMSUKY_APPLESEED_IMPHASH_MALWARE {
	meta:
		version = "1"
		date = "1/21/24"
		modified = "1/21/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "import hash of appleseed"
		category = "malware"
		malware_type = "BACKDOOR"
		malware_family = "APPLESEED"
		mitre_att = "TA0005, TA0007"
		actor_type = "APT"
		actor = "Kimsuky"
		report = "https://asec.ahnlab.com/en/60054/"
		hash = "f3a55d49562e41c7d339fb52457513ba"
		hash = "88ac3915d4204818d3360ac930497921fd35f44e"
		hash = "08d740277e6c3ba06cf6e4806132d8956795b64bb32a1433a5f09bdf941a1b72"
	condition:
		uint16(0) == 0x5a4d and pe.imphash() == "6414ec81f197039d19515b066bcf9cab"
}


import "pe"
rule APT_KIMSUKY_APPLESEED_MALWARE {
	meta:
		version = "1"
		date = "1/25/24"
		modified = "1/25/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "import hash of DLRAT"
		category = "malware"
		malware_type = "BACKDOOR"
		malware_family = "DLRAT"
		mitre_att = "TA0002, TA0003, TA0004, TA0005, TA0007, TA0011, TA0034, TA0040"
		actor_type = "APT"
		actor = "Lazarus"
		report = "https://blog.talosintelligence.com/lazarus_new_rats_dlang_and_telegram/"
		hash = "d62126246776ddf0ad64df8c78552805"
		hash = "9285f2d790c65c94e382463bfff17a642b2b9762"
		hash = "9a48357c06758217b3a99cdf4ab83263c04bdea98c347dd14b254cab6c81b13a"
	condition:
		uint16(0) == 0x5a4d and pe.imphash() == "c4a0213bb099203c783857a5e2fe3edc"
}


import "pe"
import "hash"
rule APT_NK_UNIQUE_ICON_RESOURCE_MALWARE {
	meta:
		version = "1"
		date = "1/22/24"
		modified = "1/22/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "PDF Icon used for malware, looking to see if Icon resource seen elsewhere"
		category = "malware"
		malware_type = "BACKDOOR"
		malware_family = "UNKNOWN"
		mitre_att = "TA0002, TA0003, TA0004, TA0005, TA0007, TA0011"
		actor_type = "APT"
		actor = "Lazarus"
		report = "https://www.rewterz.com/rewterz-news/rewterz-threat-alert-lazarus-apt-group-active-iocs-26/"
		hash = "8df7777ac7315c5e256ce35ea36cc73f"
		hash = "7d09178e4702790ec370e50b973528aec5bf0e3a"
		hash = "e5466b99c1af9fe3fefdd4da1e798786a821c6d853a320d16cc10c06bc6f3fc5"
	condition:
		uint16(0) == 0x5a4d and for any i in (0..pe.number_of_resources -1):(hash.md5(pe.resources[i].offset,pe.resources[i].length)=="de2c09ea6c0eeeecc88c0585f454b391")
}


rule APT_RU_TOOLMARK_MACOS_MALWARE {
	meta:
		version = "1"
		date = "1/15/24"
		modified = "1/15/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "unique paths in malicious files"
		category = "malware"
		malware_type = "BACKDOOR"
		malware_family = "multiple"
		mitre_att = ""
		actor_type = "APT"
		actor = "APT28"
		report = "https://www.bitdefender.com/blog/labs/new-xagent-mac-malware-linked-with-the-apt28/, https://www.bitdefender.com/blog/labs/new-xagent-mac-malware-linked-with-the-apt28/"
		hash = "2a06f142d87bd9b66621a30088683d6fcec019ba5cc9e5793e54f8d920ab0134"
		hash = "c1b8fc00d815e777e39f34a520342d1942ebd29695c9453951a988c61875bcd7"
		hash = "cffa1d9fc336a1ad89af90443b15c98b71e679aeb03b3a68a5e9c3e7ecabc3d4"
		hash = "96a19a90caa41406b632a2046f3a39b5579fbf730aca2357f84bf23f2cbc1fd3"
		hash = "2a854997a44f4ba7e307d408ea2d9c1d84dde035c5dab830689aa45c5b5746ea"
	strings:
		$string1 = "/Users/kazak/Library/Developer/Xcode/"
		$string2 = "/Users/kazak/Desktop/Project/osx10.6/"
		$string3 = "/Users/kazak/Desktop/Project/XAgentOSX/"
		$string4 = "/Users/kazak/Desktop/Project/komplex/"
  condition:
    any of them
}


import "dotnet"
rule CRIME_ASYNCRAT_DOTNET_METADATA_MALWARE {
	meta:
		version = "1"
		date = "1/11/24"
		modified = "1/11/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = ""
		category = "malware"
		malware_type = "BACKDOOR"
		malware_family = "ASYNCRAT"
		mitre_att = "TA0002, TA0005, TA0006, TA0007, TA0009"
		actor_type = "CRIME"
		actor = "UNK"
		report = "https://blog.cylance.com/you-me-and-.net-guids"
		hash = "143b543c696765dc049ea885c619d6ca"
		hash = "c9732161fa303dbe996a961e1a60d211b5900bae"
		hash = "c860f7d71307487badb04c598a2f20e25dc8f4275e4b1960af9470bcc97f9258"
    condition:
    	uint16(0) == 0x5a4d and (dotnet.guids[0]== "9809f3af-c32d-4bbd-a88c-3f09d9fc173f " or dotnet.assembly.name == "LimeLogger")
}


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


rule CRIME_ORVX_WEBSHELL_MALWARE {
	meta:
		version = "1"
		date = "1/20/24"
		modified = "1/20/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = ""
		category = "malware"
		malware_type = "WEBSHELL"
		malware_family = "ORVX"
		mitre_att = ""
		actor_type = "CRIME"
		actor = "UNK"
		report = "https://www.youtube.com/watch?v=BnmVXJQAQu8"
		hash = "6459a462e3511f016266e3e243b1b55d"
		hash = "3cf3cba9cd54916649774b8ac03715fbb92676d6"
		hash = "cda07c66b05bbfb85c23a345386bb526a397e7a8265abd083f7f124b08fd532e"
	strings:
		$str1 = "php /* Visit our shop orvx.pw - Shell v3 NEW"
		$str2 = /Checksum: [a-fA-F0-9]{40}/
	condition:
		filesize < 1MB and all of them
}


import "dotnet"
rule CRIME_SERPENT_INFOSTEALER_DOTNET_METADATA_MALWARE {
	meta:
		version = "1"
		date = "1/18/24"
		modified = "1/18/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = ""
		category = "malware"
		malware_type = "INFOSTEALER"
		malware_family = "SERPENT"
		mitre_att = "TA0002, TA0005, TA0006, TA0007, TA0009, TA0011"
		actor_type = "CRIME"
		actor = "UNK"
		report = "https://labs.k7computing.com/index.php/uncovering-the-serpent/"
		hash = "e97868c8431ccd922dea3dfb50f7e0b5"
		hash = "7ec3f0f2aa8dee96f0df30c9e8e529a3578ff8d8"
		hash = "cd118e082d2c035da179358c8a3c54b879b6e1b71eec2a965b78aa929b83eb11"
    strings:
        $pdb1 = "/home/pluto/Downloads/SerpentStealer/Serpent/obj/Release/net7.0/win-x64/Serpent.pdb"
    condition:
    	uint16(0) == 0x5a4d and (dotnet.guids[0]== "7e8abd91-7b70-4ee7-8184-ea4b00adafdc" or dotnet.assembly.name == "Serpent" or $pdb1) 
}


import "pe"
rule CRIME_VALLEYFALL_PDB_PATH_IMPHASH_MALWARE{
	meta:
		version = "1"
		date = "1/24/24"
		modified = "1/24/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Unique PDB Path or import hash for malware family "
		category = "malware"
		malware_type = "BACKDOOR"
		malware_family = "VALLEYFALL"
		mitre_att = "TA0002, TA0003, TA0004, TA0005, TA0006, TA0007, TA0009"
		actor_type = "CRIME"
		actor = "UNK"
		report = "https://www.avira.com/en/blog/valleyfall-spyware-in-the-wild-from-one-sample-to-a-hive-of-malware-servers"
		hash = "39970f254b9b88a8879ce5322c6112a9"
		hash = "d34dfaebb5e03dac50b2feef8a4704b2073e52c1"
		hash = "d9d6bde1ade8ae154331b7f7e50564ad17bf9368728959a0a74764ae60bec618"
	strings:
		$PDB1 = {43 3A 5C 55 73 65 72 73 5C E8 B0 B7 E5 A0 95 5C 44 65 73 6B 74 6F 70 5C 32 30 32 32 E8 BF 9C E7 A8 8B E7 AE A1 E7 90 86 67 66 69 5C 63 61 6E 67 6B 75 5C 57 69 6E 4F 73 43 6C 69 65 6E 74 50 72 6F 6A 65 63 74 5C 52 65 6C 65 61 73 65 2D 65 78 65 5C E4 B8 8A E7 BA BF E6 A8 A1 E5 9D 97 2E 70 64 62} //C:\Users\谷堕\Desktop\2022远程管理gfi\cangku\WinOsClientProject\Release-exe\上线模块.pdb 
		$PDB2 = {43 3A 5C 55 73 65 72 73 5C E8 B0 B7 E5 A0 95 5C 44 65 73 6B 74 6F 70 5C 32 30 32 32 E8 BF 9C E7 A8 8B E7 AE A1 E7 90 86 67 66 69 5C 63 61 6E 67 6B 75 5C 57 69 6E 4F 73 43 6C 69 65 6E 74 50 72 6F 6A 65 63 74} //C:\Users\谷堕\Desktop\2022远程管理gfi\cangku\WinOsClientProject\
		$PDB3 = {5C E4 B8 8A E7 BA BF E6 A8 A1 E5 9D 97 2E 70 64 62} //上线模块.pdb
	condition:
		uint16(0) == 0x5a4d and (any of ($PDB*) or pe.imphash() == "9d7ac77a44667ba5186f7bb12dfd9d42")
}


import "pe"
rule INFO_API_OVERRIDE_TOOL_SECTION_NAME {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of renamed section name added by API Override tool"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = ""
		hash = ""
		hash = ""
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".winapi" 
            )
        )
}


import "pe"
rule INFO_BOOMERANG_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of Boomerang List Builder renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = ""
		hash = ""
		hash = ""
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".boom"
            )
        )
}


import "pe"
rule INFO_CCG_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of CCG Packer (Chinese Packer) renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = ""
		hash = ""
		hash = ""
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".ccg"
            )
        )
}


rule INFO_CVE_MENTION
{
	meta:
		version = "1"
		date = "1/31/24"
		modified = "1/31/24"
		status = "DEVELOPMENT"
		sharing = "TLP:CLEAR"
		source = "N/A"
		author = "@x0rc1sm"
		description = "Attempting to find mentions of CVE-####-#### in files"
		category = "info"
		malware_type = "N/A"
		malware_family = "N/A"
		mitre_att = "N/A"
		actor_type = "APT"
		actor = "N/A"
		report = "N/A"
		hash = ""
		hash = ""
		hash = ""
	strings:
		$CVE = /CVE[-_]\d{4}[-_]\d{4}/ ascii wide
	condition:
		$CVE
}


import "pe"
rule INFO_DAStub_Dragon_Armor_protector {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of DAStub Dragon Armor protector renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = ""
		hash = ""
		hash = ""
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == "DAStub"
            )
        )
}


import "pe"
rule INFO_FIRSERIA_PUP_DOWNLOADER_SECTION_NAME {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of Firseria PUP downloaders renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = ""
		hash = ""
		hash = ""
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".mnbvcx1" or
                pe.sections[i].name == ".mnbvcx2"
            )
        )
}


rule INFO_HTTP_HTTPS_XOR
{
	meta:
		version = "1"
		date = "2/1/24"
		modified = "2/1/24"
		status = "DEVELOPMENT"
		sharing = "TLP:CLEAR"
		source = "N/A"
		author = "@x0rc1sm"
		description = "Attempting to find http or https obfuscated with single byte XOR"
		category = "info"
		malware_type = "N/A"
		malware_family = "N/A"
		mitre_att = "N/A"
		actor_type = "APT"
		actor = "N/A"
		report = "N/A"
		hash = ""
		hash = ""
		hash = ""
	strings:
		$STR1 = "https://" xor (0x01-0xff)
		$STR2 = "http://" xor (0x01-0xff)
	condition:
		any of them
}


rule INFO_KCP_MZ_FILE {
	meta:
		version = "1"
		date = "1/17/24"
		modified = "1/17/24"
		status = "DEVELOPMENT"
		sharing = "TLP:CLEAR"
		source = "https://github.com/skywind3000/kcp/blob/master/ikcp.c"
		author = "@x0rc1sm"
		description = "taking print and log reference from KCP, trying to find other implementations"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "N/A"
		hash = ""
		hash = ""
		hash = ""
	strings:
		$kcp1 = "[RO] %ld bytes" //ikcp_log(kcp, IKCP_LOG_OUTPUT, "[RO] %ld bytes", (long)size)
		$kcp2 = "[RI] %d bytes" //ikcp_log(kcp, IKCP_LOG_INPUT, "[RI] %d bytes", (int)size);
		$kcp3 = "recv sn=%lu" //ikcp_log(kcp, IKCP_LOG_RECV, "recv sn=%lu", (unsigned long)seg->sn);
		$kcp4 = "input ack: sn=%lu rtt=%ld rto=%ld" //ikcp_log(kcp, IKCP_LOG_IN_ACK, "input ack: sn=%lu rtt=%ld rto=%ld", (unsigned
		$kcp5 = "input psh: sn=%lu ts=%lu" //ikcp_log(kcp, IKCP_LOG_IN_DATA, "input psh: sn=%lu ts=%lu", (unsigned long)sn,
		$kcp6 = "input probe" //ikcp_log(kcp, IKCP_LOG_IN_PROBE, "input probe");
		$kcp7 = "input wins: %lu" //ikcp_log(kcp, IKCP_LOG_IN_WINS, "input wins: %lu", (unsigned long)(wnd));
		$kcp8 = "snd(buf=%d, queue=%d)\\n" // printf("snd(buf=%d, queue=%d)\n", kcp->nsnd_buf, kcp->nsnd_que);
		$kcp9 = "rcv(buf=%d, queue=%d)\\n" // printf("rcv(buf=%d, queue=%d)\n", kcp->nrcv_buf, kcp->nrcv_que);
		$kcp10 = "rcv_nxt=%lu\\n" // printf("rcv_nxt=%lu\n"
		$kcp11 = "rcvbuf" //ikcp_qprint("rcvbuf"
	condition:
		uint16(0) == 0x5a4d and 5 of them
}


import "magic"
rule INFO_LNK_FILE_POWERSHELL {
	meta:
		version = "1"
		date = "1/9/24"
		modified = "1//24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = ""
		author = "@x0rc1sm"
		description = "Detection of LNK File Headers/Magic header and containing powershell"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://stairwell.com/resources/the-ink-stained-trail-of-goldbackdoor/"
		hash = "99fb399c9b121ef6e60e9bdff8b324b2"
		hash = "ea0609fbf3bf0cfb2acea989126d8caafe5350ec"
		hash = "120ca851663ef0ebef585d716c9e2ba67bd4870865160fec3b853156be1159c5"
	strings:
		$s1 = "powershell" ascii wide nocase
		$s2 = "powershell -windowstyle hidden" ascii wide nocase
		$s3 = "powershell.exe" ascii wide nocase
  condition:
    (magic.type() contains "MS Windows shortcut" or uint16(0)==0x004c) and any of them
}


rule INFO_LOLBIN_RUNDLL_USAGE {
	meta:
		version = "1"
		date = "1/16/24"
		modified = "1/16/24"
		status = "DEVELOPMENT"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Attempting to find rundll32 LOLBIN usage"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://redcanary.com/blog/lolbins-abuse/"
		hash = ""
		hash = ""
		hash = ""
	strings:
		$rundll32 = "C:\\WINDOWS\\system32\\rundll32.exe" nocase wide
		$rundll64 = "C:\\Windows\\SysWOW64\\Rundll32.exe" nocase wide
	condition:
		any of them
}


import "pe"
rule INFO_MASKPE_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of MaskPE Packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = ""
		hash = ""
		hash = ""
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".MaskPE" 
            )
        )
}


import "pe"
rule INFO_MEW_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of MEW packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = ""
		hash = ""
		hash = ""
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == "MEW" 
            )
        )
}


import "magic"
rule INFO_MZ_FILE_COMPUTERNAME_FUNCTION{
	meta:
		version = "1"
		date = "2/4/24"
		modified = "2/4/24"
		status = "DEVELOPMENT"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Check if the computername with function"
		category = "info"
		malware_type = "N/A"
		malware_family = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://evasions.checkpoint.com/techniques/generic-os-queries.html"
		hash = ""
		hash = ""
		hash = ""
	strings:
		$STR1 = "GetComputerNameA" ascii wide 
		$STR2 = "GetComputerNameW" ascii wide  
		$STR3 = "GetComputerNameExA" ascii wide 
		$STR4 = "GetComputerNameExA" ascii wide 
	condition:
		(magic.type() contains "PE32 executable" or magic.type() contains "PE32+ executable" or uint16(0) == 0x5a4d) and any of them
}


import "magic"
rule INFO_MZ_FILE_DISPLAY_FUNCTION{
	meta:
		version = "1"
		date = "2/6/24"
		modified = "2/6/24"
		status = "DEVELOPMENT"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Checks if there are monitors or resolution limitations with function"
		category = "info"
		malware_type = "N/A"
		malware_family = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://evasions.checkpoint.com/techniques/generic-os-queries.html"
		hash = ""
		hash = ""
		hash = ""
	strings:
		$STR1 = "GetDesktopWindow" ascii wide 
		$STR2 = "GetWindowRect" ascii wide  
		$STR3 = "GetMonitorInfo" ascii wide 
		$STR4 = "EnumDisplayMonitors" ascii wide 
	condition:
		(magic.type() contains "PE32 executable" or magic.type() contains "PE32+ executable" or uint16(0) == 0x5a4d) and any of them
}

    
    


import "magic"
rule INFO_MZ_FILE_HARDWARE_FUNCTION{
	meta:
		version = "1"
		date = "2/5/24"
		modified = "2/5/24"
		status = "DEVELOPMENT"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Checks if there are hardware limitations with function"
		category = "info"
		malware_type = "N/A"
		malware_family = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://evasions.checkpoint.com/techniques/generic-os-queries.html"
		hash = ""
		hash = ""
		hash = ""
	strings:
		$STR1 = "GetMemoryStatusEx" ascii wide 
		$STR2 = "GetSystemInfo" ascii wide  
		$STR3 = "GetDiskFreeSpaceExA" ascii wide 
		$STR4 = "GetDiskFreeSpaceExW" ascii wide 
	condition:
		(magic.type() contains "PE32 executable" or magic.type() contains "PE32+ executable" or uint16(0) == 0x5a4d) and any of them
}


import "magic"
rule INFO_MZ_FILE_USERNAME_FUNCTION{
	meta:
		version = "1"
		date = "2/3/24"
		modified = "2/3/24"
		status = "DEVELOPMENT"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Check if the username is specific with function"
		category = "info"
		malware_type = "N/A"
		malware_family = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://evasions.checkpoint.com/techniques/generic-os-queries.html"
		hash = ""
		hash = ""
		hash = ""
	strings:
		$STR1 = "GetUserNameA" ascii wide 
		$STR2 = "GetUserNameW" ascii wide  
	condition:
		(magic.type() contains "PE32 executable" or magic.type() contains "PE32+ executable" or uint16(0) == 0x5a4d) and any of them
}


import "pe"
rule INFO_NIGHTHAWK_C2_FRAMEWORK_SECTION_NAME {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of NightHawk C2 framework (by MDSec) renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = ""
		hash = ""
		hash = ""
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".profile" 
            )
        )
}


import "magic"
rule INFO_PDF_FILE_GOOGLE_DOC
{
	meta:
		version = "1"
		date = "1/28/24"
		modified = "1/28/24"
		status = "DEVELOPMENT"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = ""
		category = "info"
		malware_type = "N/A"
		malware_family = "N/A"
		mitre_att = "N/A"
		actor_type = "APT"
		actor = "N/A"
		report = "N/A"
		hash = ""
		hash = ""
		hash = ""
	strings:
		$STR1 = /Skia\/PDF m[0-9]{1,3} Google Docs Renderer/
	condition:
		(magic.type() contains "PDF document" or uint32be(0) == 0x25504446) and $STR1
}


import "pe"
rule INFO_PESHIELD_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of PEShield Packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = ""
		hash = ""
		hash = ""
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == "PESHiELD" 
            )
        )
}


import "pe"
rule INFO_PIN_TOOL_ARTIFACT {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of PIN Tool renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = ""
		hash = ""
		hash = ""
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".pinclie" 
            )
        )
}


import "pe"
rule INFO_PROCRYPT_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of ProCrypt Packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = ""
		hash = ""
		hash = ""
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == "ProCrypt" 
            )
        )
}


import "pe"
rule INFO_RPCRYPT_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of RPCrypt Packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = ""
		hash = ""
		hash = ""
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == "RCryptor" or
                pe.sections[i].name == ".RPCryptor"
            )
        )
}


import "pe"
rule INFO_SEAUSFX_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of SeauSFX Packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = ""
		hash = ""
		hash = ""
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".seau" 
            )
        )
}


import "pe"
rule INFO_SIMPLE_PACK_SECTION_NAME {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of Simple Pack (by bagie) renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = ""
		hash = ""
		hash = ""
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".spack" 
            )
        )
}


import "pe"
rule INFO_SVKP_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of SVKP packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = ""
		hash = ""
		hash = ""
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".svkp" 
            )
        )
}


import "pe"
rule INFO_WinLicense_Protector {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of WinLicense (Themida) Protector renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = ""
		hash = ""
		hash = ""
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == "WinLicen" 
            )
        )
}


import "pe"
rule INFO_WWPACK_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of WWPACK and WWPACK32 Packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = ""
		hash = ""
		hash = ""
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == "WWPACK" or 
                pe.sections[i].name == ".WWP32"
            )
        )
}


rule INFO_YARA_RULE_FILE {
	meta:
		version = "1"
		date = "1/14/24"
		modified = "1/14/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Matching YARA rule format File"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "N/A"
		hash = ""
		hash = ""
		hash = ""
	strings:
		$rulename = {72 75 6c 65 [0-50] 7b}
		$condition = "condition:" fullword
	condition:
		filesize < 50KB and all of them
}


