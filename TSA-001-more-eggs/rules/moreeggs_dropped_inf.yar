/*
   TSA-001 detection content
   Date:   2026-07-20
   TLP:CLEAR

   Design note. The directive names in this INF do not exist as
   contiguous strings. INF line continuation splits them across
   quoted segments, so UnRegisterOCXs is written as three fragments
   and scrobj.dll as two. YARA cannot reassemble continuations, so
   this rule matches the fragments in their split form. That is a
   feature rather than a limitation: the split form is itself the
   anomaly, because no legitimate INF fragments its own directives.
*/

rule MoreEggs_Dropped_INF_Fragmented_Directives
{
    meta:
        description     = "Windows INF file with directive names fragmented by line continuation and an UnRegisterOCXs entry invoking scrobj.dll against a remote URL"
        date            = "2026-07-20"
        version         = "1.0"
        tlp             = "CLEAR"
        malware_family  = "more_eggs delivery chain"
        reference       = "TSA-001 malware analysis report"
        mitre_attack    = "T1218, T1105, T1027"
        scope           = "Dropped INF stage. Intended for %TEMP% file-write monitoring and for scanning recovered artifacts."

    strings:
        $inf_ver = "[version]"        nocase ascii wide
        $inf_sig = "signature=$windows nt$" nocase ascii wide
        $inf_str = "[strings]"        nocase ascii wide

        // Fragmented UnRegisterOCXs. Continuation splits the token.
        $frag_un  = "\"Un\\\""       ascii wide
        $frag_reg = "\"Register\\\"" ascii wide
        $frag_ocx = "OCXs="          ascii wide

        // Fragmented scrobj.dll
        $frag_scr = "\"scrob\\\""    ascii wide
        $frag_dll = "j.dll"          ascii wide nocase

        // Contiguous forms, in case a variant does not fragment
        $whole_ocx = "UnRegisterOCXs" ascii wide nocase
        $whole_scr = "scrobj.dll"     ascii wide nocase

        // Remote invocation marker
        $ni = ",NI," ascii wide nocase

    condition:
        filesize < 64KB
        and $inf_ver
        and 1 of ($inf_sig, $inf_str)
        and (
              ( all of ($frag_un, $frag_reg, $frag_ocx) )
              or ( all of ($frag_scr, $frag_dll) )
              or ( $whole_ocx and $whole_scr and $ni )
            )
}

/*
   DEPLOYMENT NOTE

   This rule is written for file scanning, not for memory. Point it at
   user temporary directories. An INF file in %TEMP% is uncommon on its
   own; an INF in %TEMP% that matches this rule has no benign explanation.

   Expected false positive sources: none identified. Legitimate INF files
   ship with drivers and reside in %SystemRoot%\INF or a vendor directory,
   and they do not fragment their own directive names.
*/
