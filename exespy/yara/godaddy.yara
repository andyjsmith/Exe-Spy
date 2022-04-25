
rule aspack {
    meta:
        description = "ASPack packed file"
        block = false
        quarantine = false

    strings:
        $mz = "MZ"
        $aspack_section = {2E61737061636B00}
        $adata_section = {2E61646174610000}

    condition:
        $mz at 0 and $aspack_section at 0x248 and $adata_section at 0x270
}


rule nkh_packer {
    meta:
        block = false
        quarantine = false
    strings:
        $mz = "MZ"
        // payload is xor compressed in the overlay with a 4-byte xor key
        $nkh_section = ".nkh_\x00\x00\x00\x00\x10\x00\x00"

    condition:
        $mz at 0 and $nkh_section in (0..0x400)
}

rule rlpack {
    meta:
        description = "RLPack packed file"
        block = false
        quarantine = false

    strings:
        $mz = "MZ"
        $text1 = ".packed\x00"
        $text2 = ".RLPack\x00"

    condition:
        $mz at 0 and $text1 in (0..1024) and $text2 in (0..1024)
}


rule sogu {
    meta:
        block = false
        quarantine = false

    strings:
        // 08E9FC6B4687C3F7FCFB86EAC870158F @ 0x4067F6
        $mov_call_sequence = { A1 ?? ?? ?? ?? FF D0 A1 ?? ?? ?? ?? FF D0 A1 ?? ?? ?? ?? FF D0 A1 ?? ?? ?? ?? FF D0 A1 ?? ?? ?? ?? FF D0 A1 ?? ?? ?? ?? FF D0 A1 ?? ?? ?? ?? FF D0 A1 ?? ?? ?? ?? FF D0 A1 ?? ?? ?? ?? FF D0 A1 ?? ?? ?? ?? FF D0 A1 ?? ?? ?? ?? FF D0 A1 ?? ?? ?? ?? FF D0 }
    
    condition:
        $mov_call_sequence
}


rule upx {
    meta:
        description = "UPX packed file"

        block = false
        quarantine = false

    strings:
        $mz = "MZ"
        $upx1 = {55505830000000}
        $upx2 = {55505831000000}
        $upx_sig = "UPX!"

    condition:
        $mz at 0 and $upx1 in (0..1024) and $upx2 in (0..1024) and $upx_sig in (0..1024)
}


rule vmprotect {
    meta:
        description = "VMProtect packed file"

        block = false
        quarantine = false

    strings:
        $mz = "MZ"
        $vmp0 = {2E766D7030000000}
        $vmp1 = {2E766D7031000000}

    condition:
        $mz at 0 and $vmp0 in (0x100..0x300) and $vmp1 in (0x100..0x300)
}

