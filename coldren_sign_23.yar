rule sign_23 { strings: $hex = { 00 00 1A 00 02 10 04 00 } condition: $hex } // Lotus 1-2-3 (v4-v5): WK4,WK5


