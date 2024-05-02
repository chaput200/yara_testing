rule sign_401 { strings: $hex = { 57 04 00 00 53 50 53 53 20 74 65 6D 70 6C 61 74 } condition: $hex } // SPSS template: SCT


