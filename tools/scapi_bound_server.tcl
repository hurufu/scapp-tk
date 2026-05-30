#!/usr/bin/env tclsh
# Dummy SCAPI socket server using the generated scapi_bind.tcl package.
#
# Generate/update the binding first:
#   tclsh asn1bind.tcl Scapi.asn1 ScapiSocketClient.asn1 > scapi_bind.tcl
#
# Run:
#   tclsh scapi_bound_server.tcl -host 127.0.0.1 -port 9999

package require Tcl 8.6

set here [file dirname [file normalize [info script]]]
if {[catch {package require scapi::bind}]} {
    source [file join $here scapi_bind.tcl]
}

namespace eval ::scapi_server {
    variable buffers
    variable cfg [dict create host 127.0.0.1 port 9999 verbose 1]
}

proc ::scapi_server::log {level msg} {
    puts stderr "[clock format [clock seconds] -format {%Y-%m-%dT%H:%M:%S%z}] \[$level\] $msg"
}
proc ::scapi_server::info  {msg} { log INFO  $msg }
proc ::scapi_server::debug {msg} { log DEBUG $msg }
proc ::scapi_server::warn  {msg} { log WARN  $msg }
proc ::scapi_server::error {msg} { log ERROR $msg }

proc ::scapi_server::usage {} {
    puts stderr "usage: tclsh scapi_bound_server.tcl ?-host 127.0.0.1? ?-port 9999? ?-quiet?"
    exit 2
}

proc ::scapi_server::parseArgs {argv} {
    variable cfg
    for {set i 0} {$i < [llength $argv]} {incr i} {
        set a [lindex $argv $i]
        switch -- $a {
            -host {
                incr i
                if {$i >= [llength $argv]} usage
                dict set cfg host [lindex $argv $i]
            }
            -port {
                incr i
                if {$i >= [llength $argv]} usage
                dict set cfg port [lindex $argv $i]
            }
            -quiet { dict set cfg verbose 0 }
            -h - --help { usage }
            default { usage }
        }
    }
}

proc ::scapi_server::accept {sock addr port} {
    variable buffers
    fconfigure $sock -translation binary -encoding binary -blocking 0 -buffering none
    set buffers($sock) ""
    fileevent $sock readable [list ::scapi_server::readable $sock]
    info "accepted $addr:$port"
}

proc ::scapi_server::closeSock {sock} {
    variable buffers
    catch {fileevent $sock readable {}}
    catch {close $sock}
    unset -nocomplain buffers($sock)
}

proc ::scapi_server::readable {sock} {
    variable buffers
    variable cfg

    if {[catch {read $sock} chunk]} {
        warn "read failed on $sock: $chunk"
        closeSock $sock
        return
    }
    if {$chunk eq ""} {
        if {[eof $sock]} {
            info "client closed $sock"
            closeSock $sock
        }
        return
    }

    append buffers($sock) $chunk
    while {[string length $buffers($sock)] > 0} {
        if {[catch {set n [::scapi::bind::frameLength $buffers($sock)]} err]} {
            warn "bad DER frame from $sock: $err; closing"
            closeSock $sock
            return
        }
        if {$n == 0} { return }

        set frame [string range $buffers($sock) 0 [expr {$n - 1}]]
        set buffers($sock) [string range $buffers($sock) $n end]
        handleFrame $sock $frame
    }
}

proc ::scapi_server::handleFrame {sock frame} {
    variable cfg
    debug "received [string length $frame] bytes: [::scapi::bind::hex $frame]"

    if {[catch {set msg [::scapi::bind::decodeDer ScapiSocketRequest $frame]} err opts]} {
        warn "decode failed: $err"
        debug $::errorInfo
        return
    }

    info "decoded ScapiSocketRequest"
    if {[dict get $cfg verbose]} {
        debug "\n[::scapi::bind::pretty $msg]"
    }

    if {[catch {set rsp [::scapi::bind::encodeSocketInteractionAck]} err]} {
        warn "failed to encode dummy response: $err"
        return
    }
    puts -nonewline $sock $rsp
    flush $sock
    debug "sent dummy interaction ack: [::scapi::bind::hex $rsp]"
}

proc ::scapi_server::main {argv} {
    variable cfg
    parseArgs $argv
    set srv [socket -server ::scapi_server::accept -myaddr [dict get $cfg host] [dict get $cfg port]]
    info "listening on [dict get $cfg host]:[dict get $cfg port]"
    vwait forever
    close $srv
}

if {[info exists argv0] && [file normalize $argv0] eq [file normalize [info script]]} {
    ::scapi_server::main $argv
}
