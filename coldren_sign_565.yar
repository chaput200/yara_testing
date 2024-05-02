rule sign_565 { strings: $hex = { EB 52 90 2D 46 56 45 2D } condition: $hex } // BitLocker boot sector (Vista): (none)


