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
		//uint16(0) == 0x5a4d and
        //($str1 or (any of ($pdb*)) or 
        //for any engine, signature in vt.metadata.signatures : (signature contains "BidenHappy")
        //) or pe.pdb_path == "C:\\Users\\test\\Desktop\\fishmaster\\x64\\Release\\fishmaster.pdb"

		uint16(0) == 0x5a4d and
        ($str1 or (any of ($pdb*))) or pe.pdb_path == "C:\\Users\\test\\Desktop\\fishmaster\\x64\\Release\\fishmaster.pdb"
}

