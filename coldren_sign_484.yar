rule sign_484 { strings: $hex = { 7B 0D 0A 6F 20 } condition: $hex } // Windows application log: LGC,LGD


