rule sign_485 { strings: $hex = { 7B 22 75 72 6C 22 3A 20 22 68 74 74 70 73 3A 2F } condition: $hex } // Google Drive Drawing link: GDRAW


