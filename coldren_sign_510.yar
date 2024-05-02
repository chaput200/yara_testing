rule sign_510 { strings: $hex = { AB 4B 54 58 20 31 31 BB 0D 0A 1A 0A } condition: $hex } // Khronos texture file: KTX


