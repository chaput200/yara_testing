rule sign_68 { strings: $hex = { 0A 16 6F 72 67 2E 62 69 74 63 6F 69 6E 2E 70 72 } condition: $hex } // MultiBit Bitcoin wallet file: WALLET


