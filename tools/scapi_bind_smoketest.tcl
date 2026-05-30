#!/usr/bin/env tclsh
package require Tcl 8.6
set here [file dirname [file normalize [info script]]]
source [file join $here scapi_bind.tcl]

proc assertEq {label a b} {
    if {$a ne $b} { error "$label: expected '$b', got '$a'" }
}

set ackValue [::scapi::bind::socketInteractionAck]
set ackDer [::scapi::bind::encodeDer ScapiSocketResponse $ackValue]
assertEq ackHex [::scapi::bind::hex $ackDer] 3006A004A0028100
set ackDecoded [::scapi::bind::decodeDer ScapiSocketResponse $ackDer]
assertEq ackRoundTrip $ackDecoded $ackValue

set reqValue [::scapi::bind::make_ScapiSocketRequest \
    req [::scapi::bind::choice_ScapiSocketRequest_req interaction \
        [::scapi::bind::choice_ScapiRequest updateInterfaces \
            [::scapi::bind::make_ScapiUpdateInterfaces \
                interfaceStatus {interfaceChipReader interfaceContactlessReader}]]]]
set reqDer [::scapi::bind::encodeDer ScapiSocketRequest $reqValue]
set reqDecoded [::scapi::bind::decodeDer ScapiSocketRequest $reqDer]
assertEq reqRoundTrip $reqDecoded $reqValue

set interaction [::scapi::bind::make_ScapiInteraction \
    what [list \
        [::scapi::bind::choice_ScapiInteraction_what_element msg crdhldrMsgPresentCard] \
        [::scapi::bind::choice_ScapiInteraction_what_element trxAmount 12345]]]
set interactionDer [::scapi::bind::encodeDer ScapiInteraction $interaction]
set interactionDecoded [::scapi::bind::decodeDer ScapiInteraction $interactionDer]
assertEq defaultLanguage [dict get $interactionDecoded language] en
assertEq whatCount [llength [dict get $interactionDecoded what]] 2

puts "ok"
puts "ack: [::scapi::bind::hex $ackDer]"
puts "request: [::scapi::bind::hex $reqDer]"
puts "interaction: [::scapi::bind::hex $interactionDer]"
