#!/usr/bin/env tclsh
# asn1bind.tcl -- small ASN.1 subset binder generator for Tcl.
#
# This is intentionally not a complete ASN.1 compiler.  It supports the
# constructs used by the supplied SCAPI modules and emits a self-contained
# Tcl DER encoder/decoder package.
#
# Usage:
#   tclsh asn1bind.tcl Scapi.asn1 ScapiSocketClient.asn1 > scapi_bind.tcl

package require Tcl 8.6

namespace eval ::asn1bind {
    variable tokens {}
    variable pos 0
    variable TYPES {}
    variable MODULE_OF_TYPE {}
    variable MODULE_TAGGING {}
    variable anonCounter 0

    variable PRIMS [dict create \
        BOOLEAN boolean \
        NULL null \
        INTEGER integer \
        ENUMERATED enum \
        UTF8String utf8 \
        PrintableString printable \
        IA5String ia5 \
        NumericString numeric \
        ANY any]
}

proc ::asn1bind::usage {} {
    puts stderr "usage: tclsh asn1bind.tcl ?-namespace ::scapi::bind? file.asn1 ..."
    exit 2
}

proc ::asn1bind::stripComments {text} {
    set out {}
    foreach line [split $text \n] {
        set i [string first -- $line]
        if {$i >= 0} { set line [string range $line 0 [expr {$i - 1}]] }
        append out $line \n
    }
    return $out
}

proc ::asn1bind::tokenize {text} {
    set text [stripComments $text]
    set out {}
    set n [string length $text]
    set i 0
    while {$i < $n} {
        set c [string index $text $i]
        if {[string is space $c]} { incr i; continue }

        set three [string range $text $i [expr {$i + 2}]]
        set two   [string range $text $i [expr {$i + 1}]]
        if {$three eq "::="} { lappend out "::="; incr i 3; continue }
        if {$three eq "..."} { lappend out "..."; incr i 3; continue }
        if {$two eq ".."}   { lappend out ".."; incr i 2; continue }

        if {$c eq "\""} {
            set j [expr {$i + 1}]
            set s {}
            while {$j < $n} {
                set d [string index $text $j]
                if {$d eq "\\" && $j + 1 < $n} {
                    append s [string index $text [expr {$j + 1}]]
                    incr j 2
                    continue
                }
                if {$d eq "\""} break
                append s $d
                incr j
            }
            lappend out [list STRING $s]
            set i [expr {$j + 1}]
            continue
        }

        if {$c eq "'"} {
            set j [expr {$i + 1}]
            set s {}
            while {$j < $n && [string index $text $j] ne "'"} {
                append s [string index $text $j]
                incr j
            }
            incr j
            if {$j < $n && [regexp {[A-Za-z]} [string index $text $j]]} {
                append s [string index $text $j]
                incr j
            }
            lappend out [list QUOTED $s]
            set i $j
            continue
        }

        if {[regexp {[A-Za-z]} $c]} {
            set j $i
            set s {}
            while {$j < $n && [regexp {[A-Za-z0-9-]} [string index $text $j]]} {
                append s [string index $text $j]
                incr j
            }
            lappend out $s
            set i $j
            continue
        }

        if {[string is digit $c]} {
            set j $i
            set s {}
            while {$j < $n && [string is digit [string index $text $j]]} {
                append s [string index $text $j]
                incr j
            }
            lappend out $s
            set i $j
            continue
        }

        if {[string first $c "\{\}\[\](),;|"] >= 0} {
            lappend out $c
            incr i
            continue
        }

        # Ignore syntax trivia that this subset parser does not need.
        incr i
    }
    return $out
}

proc ::asn1bind::peek {{offset 0}} {
    variable tokens
    variable pos
    set p [expr {$pos + $offset}]
    if {$p >= [llength $tokens]} { return "" }
    return [lindex $tokens $p]
}

proc ::asn1bind::take {} {
    variable tokens
    variable pos
    if {$pos >= [llength $tokens]} { error "unexpected end of input" }
    set t [lindex $tokens $pos]
    incr pos
    return $t
}

proc ::asn1bind::accept {tok} {
    variable pos
    if {[peek] eq $tok} { incr pos; return 1 }
    return 0
}

proc ::asn1bind::expect {tok} {
    set got [take]
    if {$got ne $tok} { error "expected '$tok', got '$got'" }
}

proc ::asn1bind::tokText {tok} {
    if {[llength $tok] == 2 && ([lindex $tok 0] eq "STRING" || [lindex $tok 0] eq "QUOTED")} {
        return [lindex $tok 1]
    }
    return $tok
}

proc ::asn1bind::isIdent {tok} {
    if {[catch {llength $tok} len] || $len != 1} { return 0 }
    return [regexp {^[A-Za-z][A-Za-z0-9-]*$} $tok]
}

proc ::asn1bind::skipBalancedBlock {} {
    set depth 0
    while {[peek] ne ""} {
        set t [take]
        if {$t in [list "\{" "(" "\["]} { incr depth }
        if {$t in [list "\}" ")" "\]"]} { incr depth -1 }
        if {$depth <= 0 && $t eq ";"} { return }
        if {$depth <= 0 && [peek 1] eq "::="} { return }
    }
}

proc ::asn1bind::skipParens {} {
    if {![accept "("]} { return }
    set depth 1
    while {$depth > 0} {
        set t [take]
        if {$t eq "("} { incr depth }
        if {$t eq ")"} { incr depth -1 }
    }
}

proc ::asn1bind::newAnon {parent name} {
    variable anonCounter
    incr anonCounter
    regsub -all {[^A-Za-z0-9_.-]} ${parent}.${name} _ base
    return ${base}__anon${anonCounter}
}

proc ::asn1bind::addType {module name def} {
    variable TYPES
    variable MODULE_OF_TYPE
    dict set def module $module
    dict set TYPES $name $def
    dict set MODULE_OF_TYPE $name $module
}

proc ::asn1bind::parseModule {text} {
    variable tokens [tokenize $text]
    variable pos 0
    variable MODULE_TAGGING

    if {[llength $tokens] == 0} { return }
    set module [take]
    expect DEFINITIONS
    set tagging EXPLICIT
    if {[peek] in {EXPLICIT IMPLICIT AUTOMATIC}} {
        set tagging [take]
        expect TAGS
    }
    expect ::= 
    expect BEGIN
    dict set MODULE_TAGGING $module $tagging

    while {[peek] ne "" && [peek] ne "END"} {
        if {[accept IMPORTS]} {
            while {[peek] ne "" && ![accept ";"]} { take }
            continue
        }
        set name [peek]
        if {![isIdent $name]} { take; continue }
        take
        if {[peek] ne "::="} {
            # Typed value assignment, e.g. example1 ScapiNotification ::= {...}
            skipBalancedBlock
            continue
        }
        expect ::= 
        set def [parseType $module $name]
        addType $module $name $def
    }
}

proc ::asn1bind::parseTag {} {
    expect "\["
    set cls CONTEXT
    set first [take]
    if {$first in {PRIVATE APPLICATION UNIVERSAL}} {
        set cls $first
        set num [take]
    } else {
        set num $first
    }
    expect "\]"
    return [dict create tagClass $cls tag $num]
}

proc ::asn1bind::parseType {module parent} {
    set t [take]
    switch -- $t {
        SEQUENCE {
            if {[accept "("]} {
                # Constraint before OF.
                set depth 1
                while {$depth > 0} {
                    set x [take]
                    if {$x eq "("} { incr depth }
                    if {$x eq ")"} { incr depth -1 }
                }
            }
            if {[accept OF]} {
                set elem [parseType $module ${parent}.element]
                set elemType [materializeInlineType $module ${parent}.element $elem]
                return [dict create kind sequenceof elementType $elemType]
            }
            expect "\{"
            set fields [parseFields $module $parent sequence]
            expect "\}"
            return [dict create kind sequence fields $fields]
        }
        SET {
            if {[accept OF]} {
                set elem [parseType $module ${parent}.element]
                set elemType [materializeInlineType $module ${parent}.element $elem]
                return [dict create kind setof elementType $elemType]
            }
            expect "\{"
            set fields [parseFields $module $parent set]
            expect "\}"
            return [dict create kind set fields $fields]
        }
        CHOICE {
            expect "\{"
            set alts [parseFields $module $parent choice]
            expect "\}"
            return [dict create kind choice alternatives $alts]
        }
        ENUMERATED {
            expect "\{"
            set names {}
            set nextVal 0
            while {[peek] ne "\}" && [peek] ne ""} {
                if {[accept ","]} continue
                if {[accept "..."]} continue
                set n [take]
                if {![isIdent $n]} { continue }
                if {[accept "("]} {
                    set v [take]
                    expect ")"
                } else {
                    set v $nextVal
                }
                lappend names $n $v
                set nextVal [expr {$v + 1}]
                accept ","
            }
            expect "\}"
            skipParens
            return [dict create kind enum values $names]
        }
        BIT {
            expect STRING
            set bits {}
            if {[accept "\{"]} {
                while {[peek] ne "\}" && [peek] ne ""} {
                    if {[accept ","]} continue
                    set n [take]
                    if {![isIdent $n]} { continue }
                    expect "("
                    set v [take]
                    expect ")"
                    lappend bits $n $v
                    accept ","
                }
                expect "\}"
            }
            skipParens
            return [dict create kind bitstring bits $bits]
        }
        OCTET {
            expect STRING
            skipParens
            return [dict create kind primitive primitive octets]
        }
        INTEGER {
            skipParens
            return [dict create kind primitive primitive integer]
        }
        BOOLEAN {
            skipParens
            return [dict create kind primitive primitive boolean]
        }
        NULL {
            return [dict create kind primitive primitive null]
        }
        UTF8String {
            skipParens
            return [dict create kind primitive primitive utf8]
        }
        PrintableString {
            skipParens
            return [dict create kind primitive primitive printable]
        }
        IA5String {
            skipParens
            return [dict create kind primitive primitive ia5]
        }
        NumericString {
            skipParens
            return [dict create kind primitive primitive numeric]
        }
        ANY {
            return [dict create kind primitive primitive any]
        }
        default {
            # Type reference, possibly with a constraint.
            skipParens
            return [dict create kind alias target $t]
        }
    }
}

proc ::asn1bind::materializeInlineType {module name def} {
    variable TYPES
    if {[dict get $def kind] eq "alias"} {
        return [dict get $def target]
    }
    set anon $name
    if {[dict exists $TYPES $anon]} {
        set anon [newAnon $name type]
    }
    addType $module $anon $def
    return $anon
}

proc ::asn1bind::parseDefaultValue {} {
    set t [take]
    return [tokText $t]
}

proc ::asn1bind::parseFields {module parent containerKind} {
    set fields {}
    set ordinal 0
    while {[peek] ne "\}" && [peek] ne ""} {
        if {[accept ","]} continue
        if {[accept "..."]} {
            lappend fields [dict create extension 1]
            accept ","
            continue
        }
        set name [take]
        if {![isIdent $name]} {
            continue
        }
        set f [dict create name $name ordinal $ordinal optional 0 default {} hasDefault 0 extension 0]
        if {[string equal [peek] "\["]} {
            set tag [parseTag]
            set f [dict merge $f $tag]
        }
        set typeDef [parseType $module ${parent}.${name}]
        set typeName [materializeInlineType $module ${parent}.${name} $typeDef]
        dict set f type $typeName
        if {[accept OPTIONAL]} { dict set f optional 1 }
        if {[accept DEFAULT]} {
            dict set f hasDefault 1
            dict set f default [parseDefaultValue]
        }
        lappend fields $f
        incr ordinal
        accept ","
    }
    return $fields
}

proc ::asn1bind::resolveKind {type {seen {}}} {
    variable TYPES
    if {[lsearch -exact $seen $type] >= 0} { error "recursive alias involving $type" }
    if {![dict exists $TYPES $type]} {
        # Built-in primitive reference fallback.
        return [dict create kind primitive primitive $type]
    }
    set def [dict get $TYPES $type]
    if {[dict get $def kind] eq "alias"} {
        return [resolveKind [dict get $def target] [linsert $seen end $type]]
    }
    return $def
}

proc ::asn1bind::typeIsChoice {type} {
    return [expr {[dict get [resolveKind $type] kind] eq "choice"}]
}

proc ::asn1bind::applyTagDefaults {} {
    variable TYPES
    variable MODULE_TAGGING

    set out $TYPES
    foreach type [dict keys $TYPES] {
        set def [dict get $TYPES $type]
        set module [dict get $def module]
        set tagging [dict get $MODULE_TAGGING $module]
        set kind [dict get $def kind]
        if {$kind ni {sequence set choice}} continue
        set listKey [expr {$kind eq "choice" ? "alternatives" : "fields"}]
        set old [dict get $def $listKey]
        set new {}
        set autoTag 0
        foreach f $old {
            if {[dict exists $f extension] && [dict get $f extension]} {
                lappend new $f
                continue
            }
            set nf $f
            if {![dict exists $nf tag]} {
                if {$tagging eq "AUTOMATIC"} {
                    dict set nf tagClass CONTEXT
                    dict set nf tag $autoTag
                }
            }
            if {[dict exists $nf tag]} {
                if {[typeIsChoice [dict get $nf type]]} {
                    dict set nf tagging explicit
                } elseif {$tagging eq "EXPLICIT"} {
                    dict set nf tagging explicit
                } else {
                    dict set nf tagging implicit
                }
            } else {
                dict set nf tagging none
            }
            lappend new $nf
            incr autoTag
        }
        dict set def $listKey $new
        dict set out $type $def
    }
    set TYPES $out
}

proc ::asn1bind::safeName {s} {
    regsub -all {[^A-Za-z0-9_]} $s _ s
    return $s
}

proc ::asn1bind::runtimeTemplate {ns} {
    return [string map [list @NS@ $ns] {# Runtime for generated ASN.1 Tcl bindings.
namespace eval @NS@ {
    variable TYPES
    variable CLASS_BITS [dict create UNIVERSAL 0 APPLICATION 1 CONTEXT 2 PRIVATE 3]
    variable CLASS_NAMES [dict create 0 UNIVERSAL 1 APPLICATION 2 CONTEXT 3 PRIVATE]
    variable UNIVERSAL_TAGS [dict create \
        boolean 1 integer 2 bitstring 3 octets 4 null 5 enum 10 utf8 12 \
        sequence 16 set 17 numeric 18 printable 19 ia5 22 any -1]
}

proc @NS@::hex {bytes} {
    binary scan $bytes H* h
    return [string toupper $h]
}

proc @NS@::fromHex {hex} {
    set hex [regsub -all {[^0-9A-Fa-f]} $hex ""]
    binary format H* $hex
}

proc @NS@::byteAt {s i} {
    binary scan [string index $s $i] cu b
    return $b
}

proc @NS@::derLength {n} {
    if {$n < 0} { error "negative DER length" }
    if {$n < 128} { return [binary format c $n] }
    set bytes {}
    set x $n
    while {$x > 0} {
        set bytes [binary format c [expr {$x & 0xff}]]$bytes
        set x [expr {$x >> 8}]
    }
    return [binary format c [expr {0x80 | [string length $bytes]}]]$bytes
}

proc @NS@::derTag {class constructed tag} {
    variable CLASS_BITS
    if {![dict exists $CLASS_BITS $class]} { error "unknown tag class $class" }
    set first [expr {[dict get $CLASS_BITS $class] << 6}]
    if {$constructed} { set first [expr {$first | 0x20}] }
    if {$tag < 31} { return [binary format c [expr {$first | $tag}]] }
    set out [binary format c [expr {$first | 0x1f}]]
    set parts [list [expr {$tag & 0x7f}]]
    set tag [expr {$tag >> 7}]
    while {$tag > 0} {
        set parts [linsert $parts 0 [expr {0x80 | ($tag & 0x7f)}]]
        set tag [expr {$tag >> 7}]
    }
    foreach p $parts { append out [binary format c $p] }
    return $out
}

proc @NS@::derTlv {class constructed tag content} {
    return [derTag $class $constructed $tag][derLength [string length $content]]$content
}

proc @NS@::readLength {dataVar} {
    upvar 1 $dataVar data
    if {[string length $data] < 1} { error "short DER length" }
    set b [byteAt $data 0]
    set data [string range $data 1 end]
    if {($b & 0x80) == 0} { return $b }
    set nbytes [expr {$b & 0x7f}]
    if {$nbytes == 0} { error "indefinite lengths are not DER" }
    if {[string length $data] < $nbytes} { error "short long-form DER length" }
    set n 0
    for {set i 0} {$i < $nbytes} {incr i} {
        set n [expr {($n << 8) | [byteAt $data $i]}]
    }
    set data [string range $data $nbytes end]
    return $n
}

proc @NS@::readTlv {dataVar} {
    variable CLASS_NAMES
    upvar 1 $dataVar data
    set original $data
    if {[string length $data] < 2} { error "short DER TLV" }
    set b [byteAt $data 0]
    set data [string range $data 1 end]
    set class [dict get $CLASS_NAMES [expr {($b >> 6) & 3}]]
    set constructed [expr {($b & 0x20) != 0}]
    set tag [expr {$b & 0x1f}]
    if {$tag == 0x1f} {
        set tag 0
        while 1 {
            if {[string length $data] < 1} { error "short high-tag-number DER tag" }
            set x [byteAt $data 0]
            set data [string range $data 1 end]
            set tag [expr {($tag << 7) | ($x & 0x7f)}]
            if {($x & 0x80) == 0} break
        }
    }
    set len [readLength data]
    if {[string length $data] < $len} { error "short DER content: need $len bytes, have [string length $data]" }
    set content [string range $data 0 [expr {$len - 1}]]
    set consumed [expr {[string length $original] - [string length $data] + $len}]
    set raw [string range $original 0 [expr {$consumed - 1}]]
    set data [string range $data $len end]
    return [dict create class $class constructed $constructed tag $tag length $len content $content raw $raw]
}

proc @NS@::readAllTlvs {content} {
    set out {}
    set rest $content
    while {[string length $rest] > 0} {
        lappend out [readTlv rest]
    }
    return $out
}

proc @NS@::frameLength {buf} {
    if {[string length $buf] < 2} { return 0 }
    set rest $buf
    if {[catch {
        set b [byteAt $rest 0]
        set rest [string range $rest 1 end]
        if {($b & 0x1f) == 0x1f} {
            while 1 {
                if {[string length $rest] < 1} { return 0 }
                set x [byteAt $rest 0]
                set rest [string range $rest 1 end]
                if {($x & 0x80) == 0} break
            }
        }
        set afterTag [string length $rest]
        set len [readLength rest]
        set lenBytes [expr {$afterTag - [string length $rest]}]
        set headerLen [expr {[string length $buf] - $afterTag + $lenBytes}]
        set total [expr {$headerLen + $len}]
        if {[string length $buf] < $total} { return 0 }
        return $total
    } err]} {
        return -code error $err
    }
}

proc @NS@::typeDef {type} {
    variable TYPES
    if {![dict exists $TYPES $type]} { error "unknown ASN.1 type '$type'" }
    return [dict get $TYPES $type]
}

proc @NS@::resolveDef {type} {
    set def [typeDef $type]
    set seen {}
    while {[dict get $def kind] eq "alias"} {
        if {[lsearch -exact $seen $type] >= 0} { error "recursive alias $type" }
        lappend seen $type
        set type [dict get $def target]
        set def [typeDef $type]
    }
    return $def
}

proc @NS@::resolvedType {type} {
    set def [typeDef $type]
    set seen {}
    while {[dict get $def kind] eq "alias"} {
        if {[lsearch -exact $seen $type] >= 0} { error "recursive alias $type" }
        lappend seen $type
        set type [dict get $def target]
        set def [typeDef $type]
    }
    return $type
}

proc @NS@::typeUniversalTag {type} {
    variable UNIVERSAL_TAGS
    set def [resolveDef $type]
    set kind [dict get $def kind]
    switch -- $kind {
        primitive {
            set p [dict get $def primitive]
            if {![dict exists $UNIVERSAL_TAGS $p]} { error "no universal tag for primitive $p" }
            return [list UNIVERSAL [dict get $UNIVERSAL_TAGS $p] [expr {$p in {sequence set}}]]
        }
        enum { return [list UNIVERSAL 10 0] }
        bitstring { return [list UNIVERSAL 3 0] }
        sequence - sequenceof { return [list UNIVERSAL 16 1] }
        set - setof { return [list UNIVERSAL 17 1] }
        choice { return {} }
        default { error "unsupported type kind $kind for tag lookup" }
    }
}

proc @NS@::typeConstructed {type} {
    set def [resolveDef $type]
    set kind [dict get $def kind]
    expr {$kind in {sequence set sequenceof setof choice}}
}

proc @NS@::tlvInfo {tlv} {
    dict create class [dict get $tlv class] tag [dict get $tlv tag] constructed [dict get $tlv constructed] hex [hex [dict get $tlv raw]]
}

proc @NS@::derIntegerContent {value} {
    if {![string is integer -strict $value]} { error "INTEGER expects an integer, got '$value'" }
    if {$value == 0} { return [binary format c 0] }
    if {$value < 0} { error "negative INTEGER values are not implemented in this binder" }
    set bytes {}
    set x $value
    while {$x > 0} {
        set bytes [binary format c [expr {$x & 0xff}]]$bytes
        set x [expr {$x >> 8}]
    }
    if {[byteAt $bytes 0] & 0x80} { set bytes [binary format c 0]$bytes }
    return $bytes
}

proc @NS@::decodeIntegerContent {content} {
    if {[string length $content] == 0} { error "empty INTEGER" }
    set n 0
    for {set i 0} {$i < [string length $content]} {incr i} {
        set n [expr {($n << 8) | [byteAt $content $i]}]
    }
    if {[byteAt $content 0] & 0x80} {
        set bits [expr {8 * [string length $content]}]
        set n [expr {$n - (1 << $bits)}]
    }
    return $n
}

proc @NS@::encodePrimitiveContent {prim value} {
    switch -- $prim {
        boolean { return [binary format c [expr {$value ? 0xff : 0x00}]] }
        integer { return [derIntegerContent $value] }
        null { return "" }
        octets {
            if {[string match -nocase "hex:*" $value]} { return [fromHex [string range $value 4 end]] }
            return $value
        }
        utf8 - printable - ia5 - numeric { return [encoding convertto utf-8 $value] }
        any {
            if {[dict exists $value hex]} { return [fromHex [dict get $value hex]] }
            if {[string match -nocase "hex:*" $value]} { return [fromHex [string range $value 4 end]] }
            return $value
        }
        default { error "unsupported primitive $prim" }
    }
}

proc @NS@::decodePrimitiveContent {prim content} {
    switch -- $prim {
        boolean {
            if {[string length $content] != 1} { error "BOOLEAN should have one content byte" }
            return [expr {[byteAt $content 0] != 0}]
        }
        integer { return [decodeIntegerContent $content] }
        null {
            if {[string length $content] != 0} { error "NULL has non-empty content" }
            return NULL
        }
        octets { return $content }
        utf8 - printable - ia5 - numeric { return [encoding convertfrom utf-8 $content] }
        any { return [dict create hex [hex $content]] }
        default { error "unsupported primitive $prim" }
    }
}

proc @NS@::enumNameToValue {def value} {
    set vals [dict get $def values]
    if {[string is integer -strict $value]} { return $value }
    if {[dict exists $vals $value]} { return [dict get $vals $value] }
    error "unknown ENUMERATED name '$value'"
}

proc @NS@::enumValueToName {def value} {
    set vals [dict get $def values]
    foreach {n v} $vals {
        if {$v == $value} { return $n }
    }
    return $value
}

proc @NS@::encodeBitStringContent {def value} {
    set bitspec [dict get $def bits]
    set max -1
    set setbits {}
    foreach b $value {
        if {[string is integer -strict $b]} {
            set ix $b
        } elseif {[dict exists $bitspec $b]} {
            set ix [dict get $bitspec $b]
        } else {
            error "unknown BIT STRING name '$b'"
        }
        lappend setbits $ix
        if {$ix > $max} { set max $ix }
    }
    if {$max < 0} { return [binary format c 0] }
    set nbits [expr {$max + 1}]
    set nbytes [expr {($nbits + 7) / 8}]
    set unused [expr {$nbytes * 8 - $nbits}]
    set bytes [lrepeat $nbytes 0]
    foreach ix $setbits {
        set byte [expr {$ix / 8}]
        set bit [expr {7 - ($ix % 8)}]
        lset bytes $byte [expr {[lindex $bytes $byte] | (1 << $bit)}]
    }
    set out [binary format c $unused]
    foreach b $bytes { append out [binary format c $b] }
    return $out
}

proc @NS@::decodeBitStringContent {def content} {
    if {[string length $content] < 1} { error "short BIT STRING" }
    set unused [byteAt $content 0]
    set data [string range $content 1 end]
    set bitnames {}
    set bitspec [dict get $def bits]
    set total [expr {[string length $data] * 8 - $unused}]
    for {set ix 0} {$ix < $total} {incr ix} {
        set byte [byteAt $data [expr {$ix / 8}]]
        set bit [expr {7 - ($ix % 8)}]
        if {$byte & (1 << $bit)} {
            set name "bit$ix"
            foreach {n v} $bitspec { if {$v == $ix} { set name $n; break } }
            lappend bitnames $name
        }
    }
    return $bitnames
}

proc @NS@::encodeType {type value} {
    set type [resolvedType $type]
    set def [typeDef $type]
    set kind [dict get $def kind]
    switch -- $kind {
        primitive {
            set prim [dict get $def primitive]
            set content [encodePrimitiveContent $prim $value]
            if {$prim eq "any"} { return $content }
            lassign [typeUniversalTag $type] cls tag constructed
            return [derTlv $cls $constructed $tag $content]
        }
        enum {
            set n [enumNameToValue $def $value]
            return [derTlv UNIVERSAL 0 10 [derIntegerContent $n]]
        }
        bitstring {
            return [derTlv UNIVERSAL 0 3 [encodeBitStringContent $def $value]]
        }
        sequence {
            return [derTlv UNIVERSAL 1 16 [encodeFields sequence $def $value]]
        }
        set {
            return [derTlv UNIVERSAL 1 17 [encodeFields set $def $value]]
        }
        sequenceof {
            set out {}
            foreach item $value { append out [encodeType [dict get $def elementType] $item] }
            return [derTlv UNIVERSAL 1 16 $out]
        }
        setof {
            set enc {}
            foreach item $value {
                set b [encodeType [dict get $def elementType] $item]
                lappend enc [list [hex $b] $b]
            }
            set out {}
            foreach pair [lsort -index 0 $enc] { append out [lindex $pair 1] }
            return [derTlv UNIVERSAL 1 17 $out]
        }
        choice {
            return [encodeChoice $def $value]
        }
        default { error "unsupported type kind $kind" }
    }
}

proc @NS@::decodeTypeFromTlv {type tlv} {
    set type [resolvedType $type]
    set def [typeDef $type]
    set kind [dict get $def kind]
    if {$kind ne "choice"} {
        lassign [typeUniversalTag $type] cls tag constructed
        if {$tag >= 0 && ([dict get $tlv class] ne $cls || [dict get $tlv tag] != $tag)} {
            error "expected $type tag $cls/$tag, got [dict get $tlv class]/[dict get $tlv tag]"
        }
    }
    set content [dict get $tlv content]
    switch -- $kind {
        primitive { return [decodePrimitiveContent [dict get $def primitive] $content] }
        enum { return [enumValueToName $def [decodeIntegerContent $content]] }
        bitstring { return [decodeBitStringContent $def $content] }
        sequence { return [decodeFields sequence $def $content] }
        set { return [decodeFields set $def $content] }
        sequenceof {
            set out {}
            foreach child [readAllTlvs $content] { lappend out [decodeTypeFromTlv [dict get $def elementType] $child] }
            return $out
        }
        setof {
            set out {}
            foreach child [readAllTlvs $content] { lappend out [decodeTypeFromTlv [dict get $def elementType] $child] }
            return $out
        }
        choice { return [decodeChoice $def $tlv] }
        default { error "unsupported type kind $kind" }
    }
}

proc @NS@::encodeImplicitContent {type value} {
    set type [resolvedType $type]
    set def [typeDef $type]
    set kind [dict get $def kind]
    switch -- $kind {
        primitive { return [encodePrimitiveContent [dict get $def primitive] $value] }
        enum { return [derIntegerContent [enumNameToValue $def $value]] }
        bitstring { return [encodeBitStringContent $def $value] }
        sequence { return [encodeFields sequence $def $value] }
        set { return [encodeFields set $def $value] }
        sequenceof {
            set out {}
            foreach item $value { append out [encodeType [dict get $def elementType] $item] }
            return $out
        }
        setof {
            set enc {}
            foreach item $value {
                set b [encodeType [dict get $def elementType] $item]
                lappend enc [list [hex $b] $b]
            }
            set out {}
            foreach pair [lsort -index 0 $enc] { append out [lindex $pair 1] }
            return $out
        }
        choice { error "CHOICE cannot be implicitly tagged" }
        default { error "unsupported type kind $kind" }
    }
}

proc @NS@::decodeImplicitContent {type content} {
    set type [resolvedType $type]
    set def [typeDef $type]
    set kind [dict get $def kind]
    switch -- $kind {
        primitive { return [decodePrimitiveContent [dict get $def primitive] $content] }
        enum { return [enumValueToName $def [decodeIntegerContent $content]] }
        bitstring { return [decodeBitStringContent $def $content] }
        sequence { return [decodeFields sequence $def $content] }
        set { return [decodeFields set $def $content] }
        sequenceof {
            set out {}
            foreach child [readAllTlvs $content] { lappend out [decodeTypeFromTlv [dict get $def elementType] $child] }
            return $out
        }
        setof {
            set out {}
            foreach child [readAllTlvs $content] { lappend out [decodeTypeFromTlv [dict get $def elementType] $child] }
            return $out
        }
        choice { error "CHOICE cannot be implicitly tagged" }
        default { error "unsupported type kind $kind" }
    }
}

proc @NS@::fieldMatches {field tlv} {
    if {[dict exists $field tag]} {
        return [expr {[dict get $tlv class] eq [dict get $field tagClass] && [dict get $tlv tag] == [dict get $field tag]}]
    }
    set type [dict get $field type]
    set def [resolveDef $type]
    if {[dict get $def kind] eq "choice"} {
        return [choiceMatches $def $tlv]
    }
    lassign [typeUniversalTag $type] cls tag constructed
    return [expr {[dict get $tlv class] eq $cls && [dict get $tlv tag] == $tag}]
}

proc @NS@::choiceMatches {def tlv} {
    foreach alt [dict get $def alternatives] {
        if {[dict exists $alt extension] && [dict get $alt extension]} continue
        if {[fieldMatches $alt $tlv]} { return 1 }
    }
    return 0
}

proc @NS@::encodeField {field value} {
    set type [dict get $field type]
    if {[dict exists $field tag]} {
        set cls [dict get $field tagClass]
        set tag [dict get $field tag]
        set mode [dict get $field tagging]
        if {$mode eq "explicit"} {
            return [derTlv $cls 1 $tag [encodeType $type $value]]
        } elseif {$mode eq "implicit"} {
            return [derTlv $cls [typeConstructed $type] $tag [encodeImplicitContent $type $value]]
        } else {
            error "unknown field tagging mode $mode"
        }
    }
    return [encodeType $type $value]
}

proc @NS@::decodeField {field tlv} {
    set type [dict get $field type]
    if {[dict exists $field tag]} {
        set mode [dict get $field tagging]
        if {$mode eq "explicit"} {
            set body [dict get $tlv content]
            set inner [readTlv body]
            if {[string length $body] != 0} { error "trailing bytes inside EXPLICIT field [dict get $field name]" }
            return [decodeTypeFromTlv $type $inner]
        } elseif {$mode eq "implicit"} {
            return [decodeImplicitContent $type [dict get $tlv content]]
        }
    }
    return [decodeTypeFromTlv $type $tlv]
}

proc @NS@::encodeFields {containerKind def value} {
    set enc {}
    foreach field [dict get $def fields] {
        if {[dict exists $field extension] && [dict get $field extension]} continue
        set name [dict get $field name]
        if {![dict exists $value $name]} {
            if {[dict get $field optional] || [dict get $field hasDefault]} { continue }
            error "missing required field '$name'"
        }
        set v [dict get $value $name]
        if {[dict get $field hasDefault] && $v eq [dict get $field default]} { continue }
        set b [encodeField $field $v]
        if {$containerKind eq "set"} {
            lappend enc [list [hex $b] $b]
        } else {
            append out $b
        }
    }
    if {$containerKind eq "set"} {
        set out {}
        foreach pair [lsort -index 0 $enc] { append out [lindex $pair 1] }
    } elseif {![info exists out]} {
        set out {}
    }
    return $out
}

proc @NS@::decodeFields {containerKind def content} {
    set tlvs [readAllTlvs $content]
    set out {}
    set unknown {}
    if {$containerKind eq "sequence"} {
        set i 0
        foreach field [dict get $def fields] {
            if {[dict exists $field extension] && [dict get $field extension]} continue
            if {$i < [llength $tlvs] && [fieldMatches $field [lindex $tlvs $i]]} {
                dict set out [dict get $field name] [decodeField $field [lindex $tlvs $i]]
                incr i
            } elseif {[dict get $field hasDefault]} {
                dict set out [dict get $field name] [dict get $field default]
            } elseif {[dict get $field optional]} {
                # absent
            } else {
                dict lappend out _missing [dict get $field name]
            }
        }
        for {} {$i < [llength $tlvs]} {incr i} { lappend unknown [tlvInfo [lindex $tlvs $i]] }
    } else {
        set used {}
        foreach tlv $tlvs {
            set matched 0
            set idx 0
            foreach field [dict get $def fields] {
                if {[dict exists $field extension] && [dict get $field extension]} { incr idx; continue }
                if {[lsearch -exact $used $idx] >= 0} { incr idx; continue }
                if {[fieldMatches $field $tlv]} {
                    dict set out [dict get $field name] [decodeField $field $tlv]
                    lappend used $idx
                    set matched 1
                    break
                }
                incr idx
            }
            if {!$matched} { lappend unknown [tlvInfo $tlv] }
        }
        set idx 0
        foreach field [dict get $def fields] {
            if {[dict exists $field extension] && [dict get $field extension]} { incr idx; continue }
            set name [dict get $field name]
            if {![dict exists $out $name]} {
                if {[dict get $field hasDefault]} { dict set out $name [dict get $field default] }
            }
            incr idx
        }
    }
    if {[llength $unknown]} { dict set out _unknown $unknown }
    return $out
}

proc @NS@::normaliseChoiceValue {value} {
    if {[catch {dict exists $value choice} ok] || !$ok} {
        if {[llength $value] == 1} { return [list [lindex $value 0] NULL] }
        if {[llength $value] == 2} { return [list [lindex $value 0] [lindex $value 1]] }
        error "CHOICE value must be dict {choice name value val} or list {name val}"
    }
    set alt [dict get $value choice]
    if {[dict exists $value value]} { set v [dict get $value value] } else { set v NULL }
    return [list $alt $v]
}

proc @NS@::encodeChoice {def value} {
    lassign [normaliseChoiceValue $value] altName altValue
    foreach alt [dict get $def alternatives] {
        if {[dict exists $alt extension] && [dict get $alt extension]} continue
        if {[dict get $alt name] eq $altName} {
            return [encodeField $alt $altValue]
        }
    }
    error "unknown CHOICE alternative '$altName'"
}

proc @NS@::decodeChoice {def tlv} {
    foreach alt [dict get $def alternatives] {
        if {[dict exists $alt extension] && [dict get $alt extension]} continue
        if {[fieldMatches $alt $tlv]} {
            return [dict create choice [dict get $alt name] value [decodeField $alt $tlv]]
        }
    }
    error "no CHOICE alternative matches tag [dict get $tlv class]/[dict get $tlv tag]"
}

proc @NS@::decodeDer {type bytes} {
    set rest $bytes
    set tlv [readTlv rest]
    if {[string length $rest] != 0} { error "trailing bytes after $type: [string length $rest]" }
    return [decodeTypeFromTlv $type $tlv]
}

proc @NS@::encodeDer {type value} {
    return [encodeType $type $value]
}

proc @NS@::decode {type bytes} { decodeDer $type $bytes }
proc @NS@::encode {type value} { encodeDer $type $value }

proc @NS@::make {type args} {
    return $args
}

proc @NS@::choice {type alt {value __SCAPI_BIND_MISSING__}} {
    if {$value eq "__SCAPI_BIND_MISSING__"} { set value NULL }
    return [dict create choice $alt value $value]
}

proc @NS@::isDictValue {value} {
    expr {![catch {dict size $value}]}
}

proc @NS@::isChoiceValue {value} {
    expr {![catch {dict exists $value choice} ok] && $ok}
}

proc @NS@::isCompoundList {value} {
    if {[catch {llength $value} n] || $n < 2} { return 0 }
    foreach item $value {
        if {![isDictValue $item]} { return 0 }
    }
    return 1
}

proc @NS@::pretty {value {indent 0}} {
    set pad [string repeat " " $indent]
    if {[isChoiceValue $value]} {
        set s "$pad[dict get $value choice]:"
        if {[dict exists $value value]} {
            append s "\n[pretty [dict get $value value] [expr {$indent + 2}]]"
        }
        return $s
    }
    if {[isCompoundList $value]} {
        set lines {}
        foreach item $value {
            lappend lines "$pad-\n[pretty $item [expr {$indent + 2}]]"
        }
        return [join $lines \n]
    }
    if {![isDictValue $value]} {
        return "$pad$value"
    }
    set lines {}
    dict for {k v} $value {
        if {[isChoiceValue $v] || [isCompoundList $v] || ([isDictValue $v] && [llength $v] > 1)} {
            lappend lines "$pad$k:\n[pretty $v [expr {$indent + 2}]]"
        } else {
            lappend lines "$pad$k: $v"
        }
    }
    return [join $lines \n]
}

proc @NS@::socketInteractionAck {} {
    return [make_ScapiSocketResponse rsp [choice_ScapiSocketResponse_rsp interaction [choice_ScapiResponse ack]]]
}

proc @NS@::encodeSocketInteractionAck {} {
    return [encodeDer ScapiSocketResponse [socketInteractionAck]]
}
}]
}

proc ::asn1bind::emit {ns} {
    variable TYPES
    applyTagDefaults
    set version 0.1
    puts "# Generated by asn1bind.tcl.  Do not edit by hand."
    puts "package require Tcl 8.6"
    puts [runtimeTemplate $ns]
    puts "namespace eval $ns \{"
    puts "    variable TYPES [list $TYPES]"
    puts "\}"

    foreach type [lsort [dict keys $TYPES]] {
        set def [dict get $TYPES $type]
        set safe [safeName $type]
        set kind [dict get $def kind]
        if {$kind in {sequence set}} {
            puts [format {proc %s::make_%s {args} { return $args }} $ns $safe]
        }
        if {$kind eq "choice"} {
            puts [format {proc %s::choice_%s {alt {value __SCAPI_BIND_MISSING__}} { if {$value eq "__SCAPI_BIND_MISSING__"} { set value NULL }; return [dict create choice $alt value $value] }} $ns $safe]
        }
        puts [format {proc %s::encode_%s {value} { encodeDer %s $value }} $ns $safe [list $type]]
        puts [format {proc %s::decode_%s {bytes} { decodeDer %s $bytes }} $ns $safe [list $type]]
    }
    puts "package provide [string trimleft $ns :] $version"
}

proc ::asn1bind::main {argv} {
    set ns ::scapi::bind
    set files {}
    for {set i 0} {$i < [llength $argv]} {incr i} {
        set a [lindex $argv $i]
        switch -- $a {
            -namespace {
                incr i
                if {$i >= [llength $argv]} usage
                set ns [lindex $argv $i]
            }
            -h - --help { usage }
            default { lappend files $a }
        }
    }
    if {![llength $files]} usage
    foreach f $files {
        set fh [open $f rb]
        set text [read $fh]
        close $fh
        parseModule $text
    }
    emit $ns
}

if {[info exists argv0] && [file normalize $argv0] eq [file normalize [info script]]} {
    ::asn1bind::main $argv
}
