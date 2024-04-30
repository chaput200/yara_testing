import "pe"

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
        ($str1 or (any of ($pdb*))
        ) or pe.pdb_path == "C:\\Users\\test\\Desktop\\fishmaster\\x64\\Release\\fishmaster.pdb"
}

//11f21d08f819dea21a09c602a4391142a5648f3e17a07a24d41418fcc17ea83f	TELF = T110044B03FB8594FBC0C9D5B2C6CFC0AADA6270546325152B3DCEA3151919B318F6EBA7
//43ae4e624413a587667027c03416d78b2515ac9081b8c9c967aadb1157f49e55	TELF = T110044B03FB8594FBC0C9D5B2C6CFC0AADA6270546325152B3DCEA3151919B318F6EBA7
//1400b65d7200adf2b15be4531dac25bfe6b79391b686da33a0ffd67b5eefcc4e	TELF = T110044B03FB8594FBC0C9D5B2C6CFC0AADA6270546325152B3DCEA3151919B318F6EBA7
//2ada1b48457c169cf3f80e248190374102615e2c89b70e574fba4ddc09b5fcd5	TELF = T1AE244907FB4554BEC0DAC6B2C7DFC1AADE2530886335912A7CCEA6101925B309F6E767
//c65c435737ac02132d9dfeb6ec1d7d903648f61ecdda8a85b4250f064cb4673f	TELF = T193F47C03FBD164BEC4D5D970C78FE026DFB5B0486122617B79CA6A006E56A30AF1F693
//08dd5a9fdc387855fb5a23c167abec63b22272f66de099155036c5ce7e4deeb8	TELF = T1D4D2D937F7A2C774D0D9A3701DDB4861F5B3B0F06732221B260656776A82B881F1FA5A
//d0fec5c5e2687e76af07a4a3c6e2e2b02789838c0b802f5041443ab482bc3498	TELF = T1D1154C03F7A894FAD4E9C8704B8FC5B3DC217C484276257F3A96A6012A7AE215F1DB71
//07aa739fa4942cfd68d4a075568456797f11ae34db5cd56f88d80185bc1d7a29	TELF = T1FF155C03F7A894FAD4E9C8704B8FC5B3DC217C484276257F3A96A6012A7AE215F1DB71
//d67aebfafa347a21805dbded3fa310e2268a5d2255fcb7f1c8004502a95e7538	TELF = T1436423D4852AB1F2F3E0C777BB5A1829BDD64B0532C017F46CE1AD940A3AA6A0544DCF
//e909c4dac832e9d1ecd1673c5bff6e1939d9c832a2509cb64931e4aa1e334077	TELF = T1DC154B03B7A894FAD4EAC4704B8FC5B3DC217C484276257F3A96A6012A7AE315F1DB71
//c10a3a78cdf1e48189ac270767f7f718bd15a9d4e48e580a9ef6ceff5f4abf46	TELF = T1616423C4726461DAFD2A69BB1A2283DC7545E3168BD1E1EE46874063AF4CC7263C32DF
//8019b7deaf41b48c38b8b48e016f208a28e0909d437d4e35e3e35f7995758564	TELF = T181154B03B7A894FAD4EAC4704B8FC5B3DC217C484276257F3A96A6012A7AE315F1DB71

import "magic"
import "elf"
rule APT_CN_LINUX_RSHELL_MALWARE {
	meta:
		version = "1"
		date = "1/7/24"
		modified = "1/7/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Linux Malware Pivot with TELF hashes"
		category = "malware"
		malware_type = "BACKDOOR"
		malware_family = "RSHELL/SYSUPDATE"
		mitre_att = "TA0002,TA0003,TA0004,TA0005,TA0006,TA0007,TA0011"
		actor_type = "APT"
		actor = "LuckyMouse/EmissaryPanda/APT27/BronzeUnion/IronTiger"
		report = "https://www.trendmicro.com/en_ph/research/23/c/iron-tiger-sysupdate-adds-linux-targeting.html, https://www.trendmicro.com/en_ph/research/22/h/irontiger-compromises-chat-app-Mimi-targets-windows-mac-linux-users.html, "
		hash = "a4f702e862fff5b71cb0941f39843437"
		hash = "5afb47de3a6deae177193f8e79db9a04da8de3cb"
		hash = "11f21d08f819dea21a09c602a4391142a5648f3e17a07a24d41418fcc17ea83f"
	condition:
		(magic.type() contains "ELF" or uint32(0) == 0x464c457f) and 
		(
		elf.telfhash() == "t110044b03fb8594fbc0c9d5b2c6cfc0aada6270546325152b3dcea3151919b318f6eba7" or
		elf.telfhash() == "t1ae244907fb4554bec0dac6b2c7dfc1aade2530886335912a7ccea6101925b309f6e767" or
		elf.telfhash() == "t193f47c03fbd164bec4d5d970c78fe026dfb5b0486122617b79ca6a006e56a30af1f693" or
		elf.telfhash() == "t1d4d2d937f7a2c774d0d9a3701ddb4861f5b3b0f06732221b260656776a82b881f1fa5a" or
		elf.telfhash() == "t1d1154c03f7a894fad4e9c8704b8fc5b3dc217c484276257f3a96a6012a7ae215f1db71" or
		elf.telfhash() == "t1ff155c03f7a894fad4e9c8704b8fc5b3dc217c484276257f3a96a6012a7ae215f1db71" or
		elf.telfhash() == "t1436423d4852ab1f2f3e0c777bb5a1829bdd64b0532c017f46ce1ad940a3aa6a0544dcf" or
		elf.telfhash() == "t1dc154b03b7a894fad4eac4704b8fc5b3dc217c484276257f3a96a6012a7ae315f1db71" or
		elf.telfhash() == "t1616423c4726461dafd2a69bb1a2283dc7545e3168bd1e1ee46874063af4cc7263c32df" or
		elf.telfhash() == "t181154b03b7a894fad4eac4704b8fc5b3dc217c484276257f3a96a6012a7ae315f1db71"
		)
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


