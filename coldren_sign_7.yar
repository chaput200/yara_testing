rule sign_7 { strings: $hex = { 00 00 00 00 62 31 05 00 09 00 00 00 00 20 00 00 00 09 00 00 00 00 00 00 } condition: $hex } // Bitcoin Core wallet.dat file: DAT


