rule sign_29 { strings: $hex = { 00 01 00 00 4D 53 49 53 41 4D 20 44 61 74 61 62 61 73 65 } condition: $hex } // Microsoft Money file: MNY


