rule sign_250 { strings: $hex = { 4A 41 52 43 53 00 } condition: $hex } // JARCS compressed archive: JAR


