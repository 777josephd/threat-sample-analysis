/*
   TSA-001 detection content
   Date:   2026-07-20
   TLP:CLEAR

   Design note. This rule is deliberately structural. The obfuscation
   vocabulary in this family is resampled per build by the delivery
   server, so any rule keyed on the observed variable names will fail
   against the next sample. The features below describe the shape of
   the command line, not its contents.
*/

rule FIN6_MoreEggs_LNK_Dropper_Structural
{
    meta:
        description     = "Windows shortcut carrying a heavily obfuscated cmd.exe command line consistent with the more_eggs LNK dropper stage"
        date            = "2026-07-20"
        version         = "1.0"
        tlp             = "CLEAR"
        malware_family  = "more_eggs delivery chain"
        actor           = "FIN6 / Venom Spider builder"
        reference       = "TSA-001 malware analysis report"
        hash            = "4e18f606f7a31ffbea632ceaffad77689f810a3cde26d2a913d4530eaae5c5d1"
        mitre_attack    = "T1204.002, T1027.010, T1059.003"
        scope           = "LNK stage only. Does not detect the dropped INF, the scriptlet, or the more_eggs payload."

    strings:
        // ShellLinkHeader: HeaderSize 0x0000004C followed by LinkCLSID
        $hdr = { 4C 00 00 00 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }

        // Relative path traversal. Six levels observed; four or more is anomalous.
        $traversal = "..\\..\\..\\..\\" wide ascii

        // Interpreter and the load-bearing delayed expansion flag
        $cmd  = "cmd.exe" wide ascii nocase
        $vflg = "/v"      wide ascii nocase
        $cflg = "/c"      wide ascii nocase

        // Delayed expansion tokens. Counted, not matched individually.
        $expand = /![a-zA-Z]{3,14}!/ wide ascii

        // Chain tail. Either is sufficient; both are expected.
        $inf   = ".inf"     wide ascii nocase
        $sys32 = "system32" wide ascii nocase

    condition:
        $hdr at 0
        and filesize > 3KB and filesize < 64KB
        and $traversal
        and $cmd
        and $vflg and $cflg
        and #expand > 20
        and any of ($inf, $sys32)
}

/*
   TUNING REQUIRED BEFORE DEPLOYMENT

   The threshold #expand > 20 is set conservatively. The measured
   expansion count for the TSA-001 sample has not been recorded. Run
   the sample against this rule with the threshold lowered to 1 and
   read the actual count, then set the threshold to roughly half of
   the measured value. Record the measured value in the report.

   Expected false positive sources: none identified. A benign shortcut
   containing more than twenty delayed-expansion tokens and a four-level
   relative path to cmd.exe has no ordinary explanation. Validate against
   a benign shortcut corpus before enabling in production.
*/
