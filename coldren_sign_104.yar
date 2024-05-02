rule sign_104 { strings: $hex = { 23 20 54 68 69 73 20 69 73 20 61 6E 20 4B 65 79 } condition: $hex } // Google Earth Keyhole Placemark file: ETA


