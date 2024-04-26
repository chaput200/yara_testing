

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
rule INFO_ASPACK_PACKER {
	meta:
		version = "1"
		date = "1/5/24"
		modified = "1/5/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of ASPACK Packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "b456385b1e0cb6c85066b7618e52758a"
		hash = "9ff07edb51a737e4a314cc0e495788b8c7b8d02c"
		hash = "866028bad1dd43edb256416a71896584e02294cba419dd508a8a2afc81ac5ebc"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".aspack" or
                pe.sections[i].name == ".adata" or
                pe.sections[i].name == "ASPack" or
                pe.sections[i].name == ".ASPack"
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
rule INFO_CRUNCH_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of Crunch 2.0 Packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "22c4b235e0de288617767567125706bf"
		hash = "3bd508a7733e22bba1c49f0934317d11b9e34ad4"
		hash = "94f3b1421488727995d368fb32909f0a0b04e447ba33075c98592e769db78595"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == "BitArts"
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


import "magic"
rule INFO_ELF_FILE{
	meta:
		version = "1"
		date = "1/8/24"
		modified = "1/8/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "N/A"
		author = "@x0rc1sm"
		description = "Detection of ELF File Headers/Magic Filename"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "N/A"
		hash = "d7efa4eb322759bdeddbfd8345fed9b1"
		hash = "2fa3717308c8e083b6e57fc159f15ccccc430366"
		hash = "fcdd043b1f278ce8cae56e7b651ffe7c0587054f403a8643470b20fc9e05d051"
    condition:
        (magic.type() contains "ELF" or uint32(0) == 0x464c457f)
}		


import "pe"
rule INFO_ENIGMA_PROTECTOR {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of Enigma Protector renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "5b23d6b5fb0b7195231ec24d5861ef71"
		hash = "6b60c43b3e0e9e56d7b378821ba497ed154f3195"
		hash = "afefa95de9d2a7f8f78b2d07edb791f04cae8910e32925167a015508ece2d790"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".enigma1" or 
                pe.sections[i].name == ".enigma2" 
            )
        )
}


import "pe"
rule INFO_EPACK_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of Epack packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "5c6078d30b23cc15da0c7db7adcab4b1"
		hash = "7412d67f7501c51535127438eadf27ae03610549"
		hash = "782198d1eda4866e04ce625424176a0d924ef78ab7dbf7351c129e71f36a3eb4"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == "!EPack"
            )
        )
}


import "pe"
rule INFO_EPL_BUILD {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of Built with EPL renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "cab2bfd427c4f300f4fac81150a4f771"
		hash = "5bea3b19e592a1beef2ca96ce00706f22dc23cbc"
		hash = "73e1de247b452acd32872537084cdaf97bf8a4362a549b00b173560a2b82ab1d"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".ecode" or 
                pe.sections[i].name == ".edata" 
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


import "pe"
rule INFO_GENTEE_INSTALLER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of Gentee Installer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "ccefb390d79166a577fc3daf036e902d"
		hash = "11ef5788819e03e9f74ec059261f2a16c3da7d58"
		hash = "a35539d69fce5105782aade3ec061c49d1ecab5e2961e491de87f10802d3da79"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".gentee" 
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


import "magic"
rule INFO_HWP_FILE {
	meta:
		version = "1"
		date = "1/2/24"
		modified = "1/2/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of HWP File Headers/Magic Filename"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://securelist.com/scarcruft-surveilling-north-korean-defectors-and-human-rights-activists/105074/"
		hash = "c155f49f0a9042d6df68fb593968e110"
		hash = "9d6fa64e0c0f3ec7442cb72bfaa016c3e3d7ff52"
		hash = "81ee247eb8d9116893e5742d12b2d8cd2835db3f751d6be16c2e927b892c5dc7"
  condition:
    magic.type() contains "Hangul (Korean) Word Processor File" 
}


import "pe"
rule INFO_ImpRec_Section_name {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of ImpRec created section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "434c3add35ae58605c17dde7cf4c72a4"
		hash = "abe91cb89d2e9d948c912f941cfb2fdf11c0ff4d"
		hash = "509aa1cb0581be5a930b2d03865680bc6060fbe1e5479aa464553e2adcf0c3ee"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".mackt" 
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


import "pe"
rule INFO_KKRUNCHY_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of kkrunchy packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "e2f4598f958cf3647dec16c5d09fb9ae"
		hash = "cb817a994afd5fc552907bfc012e05f814fed4fe"
		hash = "3dd4bfa875061d222e57ae998041b1e22347a226cde106666e2a7a11d642b260"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == "kkrunchy" 
            )
        )
}


import "magic"
rule INFO_LNK_FILE {
	meta:
		version = "1"
		date = "1/1/24"
		modified = "1/1/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "https://csirt.ninja/?p=1103"
		author = "@x0rc1sm"
		description = "Detection of LNK File Headers/Magic Filename"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.pwc.co.uk/cyber-security/pdf/pwc-uk-operation-cloud-hopper-technical-annex-april-2017.pdf"
		hash = "0b6845fbfa54511f21d93ef90f77c8de"
		hash = "cc3b6cafdbb88bd8dac122e73d3d0f067cf63091"
		hash = "6d910cd88c712beac63accbc62d510820f44f630b8281ee8b39382c24c01c5fe"
  condition:
    (magic.type() contains "MS Windows shortcut" or uint16(0)==0x004c) and
    filesize < 10KB 
}


import "magic"
rule INFO_LNK_FILE_CMD_LINE {
	meta:
		version = "1"
		date = "1/9/24"
		modified = "1//24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = ""
		author = "@x0rc1sm"
		description = "Detection of LNK File Headers/Magic header and containing CMD.EXE"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://blog.eclecticiq.com/mustang-panda-apt-group-uses-european-commission-themed-lure-to-deliver-plugx-malware"
		hash = "67c8b4f7e6e79f9747e38163ad69a3fb"
		hash = "3c039fbf5215da7c2f3be18831da7a35a8f168b6"
		hash = "2c0273394cda1b07680913edd70d3438a098bb4468f16eebf2f50d060cdf4e96"
	strings:
		$s1 = "C:\\Windows\\System32\\cmd.exe" ascii wide nocase
		$s2 = "cmd.exe" ascii wide nocase
  condition:
    (magic.type() contains "MS Windows shortcut" or uint16(0)==0x004c) and any of them
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


import "pe"
rule INFO_MPRESS_PACKER {
	meta:
		version = "1"
		date = "1/4/24"
		modified = "1/4/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of MPRESS Packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/basic-packers-easy-as-pie/"
		hash = "ac61852921c771e1d268b50a5979af49"
		hash = "3041bb48df6a2afc8cd40c24db17f5bf888c0b7a"
		hash = "fb0204d2076d57890c12848ceb39cd6daf40c77c8a434d60e4b6fb4fc113d678"
	strings:
		$STR1 = ".MPRESS1" ascii wide nocase fullword
		$STR2 = ".MPRESS2" ascii wide nocase fullword
  condition:
  	uint16(0) == 0x5A4D or all of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".MPRESS1" or
                pe.sections[i].name == ".MPRESS2" 
            )
        )
}


import "magic"
rule INFO_MZ_FILE {
	meta:
		version = "1"
		date = "1/3/24"
		modified = "1/3/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of Windows Executable File Headers/Magic Filename"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "n/a"
		hash = "ec8db58467d8e2e2221635c592fcca1a"
		hash = "e0215d156d2dc59b6259fd5ff792dc740626c8fa"
		hash = "aebff5134e07a1586b911271a49702c8623b8ac8da2c135d4d3b0145a826f507"
  condition:
    (magic.type() contains "PE32 executable" or magic.type() contains "PE32+ executable" or uint16(0) == 0x5a4d)
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
rule INFO_NEOLITE_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of Neolite Packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "6a46ce5d22772e496a82755d235f5e3f"
		hash = "fe01b8cd0c53d390252097f1bf80ae2d3ca5ee67"
		hash = "589fa885e561d591ed908dc39459997e78699d7a2efb4d5b49bc658ced378f9e"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".neolite" or 
                pe.sections[i].name == ".neolit"
            )
        )
}


rule INFO_NESTED_ZIP {
	meta:
		version = "1"
		date = "1/23/24"
		modified = "1/23/24"
		status = "DEVELOPMENT"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Attempting to find zip(s) inside of zip files, when analyzing in bulk came across double zipped files"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "N/A"
		hash = "f75d2d5b02fa8bfaa8f9f67f48fa95ed"
		hash = "fdca3351e265f125688cefc8ae3e5cfdc79bc567"
    hash = "5aa582f0bb41cfdd621f218ac7f054dd7be78f0b8d228be38a5112a4cc20e4ad"
	strings:
		$header = {50 4b 03 04}
		$zip_hex = {2e 7a 69 70}
		$zip_ascii = ".zip" nocase
		$zip_head1 = {50 4b 01 02}
		$zip_head2 = {50 4b 03 04}
		$zip_head3 = {50 4b 05 06}
		$zip_head4 = {50 4b 07 08}
	condition:
		$header at 0 and ($zip_hex in (30..180) or $zip_ascii in (30..180) or $zip_head1 in (30..180) or $zip_head2 in (30..180) or $zip_head3 in (30..180) or $zip_head4 in (30..180))
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


import "pe"
rule INFO_NSPACK_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of NSPACK Packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "ec7a1955e6a826d407b225111c1a384d"
		hash = "9310d50074d488797703f8b4ab6229a74e7c2127"
		hash = "f71d3c3db66f57a13924571d50c6816f8bf515327e57267782911ba446b5b3eb"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".nsp0" or 
                pe.sections[i].name == ".nsp1" or
                pe.sections[i].name == ".nsp2" or
                pe.sections[i].name == "nsp0" or 
                pe.sections[i].name == "nsp1" or
                pe.sections[i].name == "nsp2"
            )
        )
}


import "magic"
rule INFO_PDF_FILE {
	meta:
		version = "1"
		date = "1/2/24"
		modified = "1/2/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of PDF File Headers/Magic Filename"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.sentinelone.com/blog/malicious-pdfs-revealing-techniques-behind-attacks/"
		hash = "d949720af989e5e492570f0918362867"
		hash = "fddcc1b602f0583833ab549373269ed14e71f0a5"
		hash = "19ac1c943d8d9e7b71404b29ac15f37cd230a463003445b47441dc443d616afd"
  condition:
    (magic.type() contains "PDF document" or uint32be(0) == 0x25504446)
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
rule INFO_PEBUNDLE_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of PEBundle Packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "6f1dfd1d01d868bdce1566e4593a5a36"
		hash = "f77dee085637e35ab8f8240f1169a8ae67d95fdb"
		hash = "481966d0c2f96a1c74b1f7e46aa4b040087cb38307f737dc15563a44bd64f0ad"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == "pebundle" or 
                pe.sections[i].name == "PEBundle"
            )
        )
}


import "pe"
rule INFO_PECOMPACT_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of PECompact Packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "efc913c43be24b76da3cf878552bf689"
		hash = "2bcd7b067784a3317f1dfbfd3e0ab1901399410d"
		hash = "43111606af74d300f30bf6de21e01694047f236b3c57d79ee2cc5025dbeec929"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == "PEC2TO" or 
                pe.sections[i].name == "PEC2MO" or 
                pe.sections[i].name == "PEC2" or
                pe.sections[i].name == "pec" or
                pe.sections[i].name == "pec1" or
                pe.sections[i].name == "pec2" or
                pe.sections[i].name == "pec3" or
                pe.sections[i].name == "pec4" or
                pe.sections[i].name == "pec5" or
                pe.sections[i].name == "pec6"
            )
        )
}


import "pe"
rule INFO_PELOCK_PROTECTOR {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of PELock Protector renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "ea86363d5c9688b9d3d32d94e5d49b92"
		hash = "010faf66635243e7f4d337ecc397bfa9db9ce60f"
		hash = "2d8e22c485c4e7ff511c7dae1b4e186d5ec5e2af29e12372d8403b03867c6723"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == "PELOCKnt" 
            )
        )
}


import "pe"
rule INFO_PERPLEX_PROTECTOR {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of Perplex PE-Protector renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "e9a2ce9fa89941ed4aa90a0b1fda071e"
		hash = "bc7bffb6b577b2876c760984b03cb2568e918c42"
		hash = "a6b85778185e469b23e0da8d76f7c9019e2c24463d0a52b96b554aaaf2695462"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".perplex" 
            )
        )
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
rule INFO_PESPIN_SECTION_NAME {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of Some version os PESpin renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "30633847385092004d786595e69c33dd"
		hash = "fbaad9d6b0975c7e16bc0dc65a0f349935e58596"
		hash = "6592c0c6b8ce359c1f642d9d8bc2014fd7d2c276e602f48233b38a275d127e60"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".taz" 
            )
        )
}


import "pe"
rule INFO_PETITE_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of Petite Packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "e3048c234c314bd06c60e128216b8578"
		hash = "f9dff7b1d0aaf208ddd1061a22b9ed921118904c"
		hash = "b23f3b7e4f8e97e597da88a9638a3474df7eee5ad2a627b6caf0ef11657c1e1c"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".petite" 
            )
        )
}


rule INFO_PHP_BASE64_EVAL{
	meta:
		version = "1"
		date = "1/19/24"
		modified = "1/19/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Trying to find base64 obfuscation in PHP files"
		category = "INFO"
		malware_type = "N/A"
		malware_family = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.youtube.com/watch?v=BnmVXJQAQu8"
		hash = "6459a462e3511f016266e3e243b1b55d"
		hash = "3cf3cba9cd54916649774b8ac03715fbb92676d6"
		hash = "cda07c66b05bbfb85c23a345386bb526a397e7a8265abd083f7f124b08fd532e"
    strings:
        $str1 = "<?php"
        $str2 = /eval\s?\(\s?base64_decode\s?\("[A-Za-z0-9+\/]{0,500}/
    condition:
    	 $str1 at 0 and filesize < 1MB and $str2
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
rule INFO_RAMNIT_VIRUS_MARKER_SECTION_NAME {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of Ramnit virus marker renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "6d6101721e2fcd45ae880f3c89ad4bfe"
		hash = "4d146182111be7fe7ff6e48cebc4ae074c9f9964"
		hash = "d9d8a146e5c0180c076c89a9bedd6b9c311a027794078495447d9ed38cb186ce"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".rmnet" 
            )
        )
}


import "pe"
rule INFO_RLPACK_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of RLPack Packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "7baf89a70ac2cd239815c9dd0af7a5a6"
		hash = "2b133eaf40810da8d40ac4de3b849799c92c5001"
		hash = "a7a012169519d31fec73db83f628720528c68ce3d5bb462c517c53b8e5f004ba"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".packed" or 
                pe.sections[i].name == ".RLPack"
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


import "magic"
rule INFO_RTF_FILE{
	meta:
		version = "1"
		date = "1/2/24"
		modified = "1/2/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "N/A"
		author = "@x0rc1sm"
		description = "Detection of RTF File Headers/Magic Filename"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "N/A"
		hash = "ca032100ce044e0bc1e0a53263ac68e6"
		hash = "78db48c4a735802ea4b21d638b0f0aa37cca4150"
		hash = "2a533047b555a33bcc5d4ad9fb6f222b601f9d643be908c940c38284aa4354b6"
  condition:
		(magic.type() contains "Rich Text Format" or uint32be(0) == 0x7B5C7274)
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
rule INFO_SHRINKER_SECTION_NAME {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of Shrinker renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "b48ed7a1a8713b20ae04fab1102464a4"
		hash = "1d08c1ee244d66cf2c908969d5bca2f80b1cb43b"
		hash = "1f90241469ef61bc3393cbbf0216a7fd2ea95546fc358cb2ed61960fcf0c645b"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".shrink1" or  
                pe.sections[i].name == ".shrink2" or
                pe.sections[i].name == ".shrink3"
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
rule INFO_STARFORCE_PROTECTION_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of StarForce Protection renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "4aaa34a365a1f5751cbc0f3b4139ab32"
		hash = "4e5b5f786c6970b99a4b5902b21aef7e2db0bbdc"
		hash = "e58e4b7f670d95ee270c10d53811d1f3f4cd2c642f656d2214d94e45745f9fe9"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".sforce3" 
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
rule INFO_THEMIDA_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of Themida Packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "ff121cdd62bafa619e2485c397098f7f"
		hash = "d0b5ad3f3141b4390480f52b456864ffc322e65e"
		hash = "d0bf3cb889cff503c8cffe2a883f191200506a6ef34db658c7173ee08da68fc3"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == "Themida" or
                pe.sections[i].name == ".Themida"
            )
        )
}


import "pe"
rule INFO_TSULOADER_SECTION_NAME {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of TSULoader renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "717f2c41817163e959e537d6fcc6e47e"
		hash = "8f5f5584141f0ac5e8aa44fec10a66b6df96d3a0"
		hash = "7d403eab8b54213c21fd81950e8e8ba57df5a715251e019869759379202265d5"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".tsuarch" or
                pe.sections[i].name == ".tsustub"
            )
        )
}


import "pe"
rule INFO_UNKNOWN_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of Unknown Packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "7baf89a70ac2cd239815c9dd0af7a5a6"
		hash = "2b133eaf40810da8d40ac4de3b849799c92c5001"
		hash = "a7a012169519d31fec73db83f628720528c68ce3d5bb462c517c53b8e5f004ba"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".packed" 
            )
        )
}


import "pe"
rule INFO_UPACK_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of Upack packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "dca1503c73cdd9aef6e771786e5676f0"
		hash = "531f62a49097b79292e30d79ca2870165bbd5295"
		hash = "c7afdd5cfd597e820af8c21bdae641ae16ef74c28c4053c87cdd32c779b0da4d"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".Upack" or
                pe.sections[i].name == ".ByDwing"
            )
        )
}


import "pe"
rule INFO_UPX_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of UPX packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "24198b5d069222522a509a10129201ec"
		hash = "e99e91b6fc3d02e47e998be8995cd11b3293aaed"
		hash = "daa6a70b32cde752ad0e75bd36504b7953d8e077792080a6e700cff5f7321b01"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == "UPX!" or
                pe.sections[i].name == "UPX0" or
                pe.sections[i].name == "UPX1" or 
                pe.sections[i].name == "UPX2" or 
                pe.sections[i].name == "UPX3" or 
                pe.sections[i].name == ".UPX0" or 
                pe.sections[i].name == ".UPX1" or 
                pe.sections[i].name == ".UPX2"
            )
        )
}


import "pe"
rule INFO_VMPROTECT_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of VMProtect packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "107537459b6745600eb335ae5e83d340"
		hash = "565ff1685082d3323b54103d7b9ec88d8659b6a2"
		hash = "7442abeabd2a3db17f8f2bec66dfbd8af4988426f3768186bbcf94cdaeb51232"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".vmp0" or
                pe.sections[i].name == ".vmp1" or
                pe.sections[i].name == ".vmp2"
            )
        )
}


import "pe"
rule INFO_VPROTECT_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of Vprotect Packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "83abc83ac4a8a97de062b56f2518a8b1"
		hash = "3275e01497b20161067ad36b964ac719898c0094"
		hash = "99f6d0c080cd05ae1466385b125ccd6744a86c4bae7973441c4147948b8b31e9"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == "VProtect" 
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
rule INFO_WINZIP_SELF_EXTRACTOR_SECTION_NAME {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of renamed section name added by WinZip Self-Extractor"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "32c956ef503b080620e60905d77d2730"
		hash = "6f7a9d1896d1e454def52bde2f8a05f445b30555"
		hash = "8afdffe950611d59703520b08904ce23d442defb1875468efd57f4639298f1aa"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == "_winzip_" 
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


rule INFO_XOR_DOS_HEADER {
	meta:
		version = "1"
		date = "1/3/24"
		modified = "1/3/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of This Program Cannot XOR'd"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "N/A"
		hash = "1e4f9b61339c3a0b5ca1537913b08662"
		hash = "d80d41986d3c5f168cb0e55b84e81998a19346d5"
		hash = "2f114b77d54dee4292a3411da5bd105b59b2b152d91448900c8bb65c33a494b5"
    strings:
        $string = "This program cannot be run in DOS mode" xor (0x01-0xff)
    condition:
        $string in (200..filesize)
}


import "pe"
rule INFO_Y0DA_PROTECTOR {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of Y0da Protector renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "f3dd8e593b91c911556fad99b07dfd1c"
		hash = "eb9e98484a16f56b58236ba89d8edbaf92ccbbc2"
		hash = "d8581aeacd0429934eaa279d14a86d473c405d85cd9904237ba0afafbe6ae8f0"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".yP" or 
                pe.sections[i].name == ".y0da"
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


