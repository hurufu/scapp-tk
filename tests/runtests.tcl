#!/usr/bin/env tclsh

package require tcltest

set testdir [file dirname [file normalize [info script]]]
set root [file dirname $testdir]

tcltest::configure -testdir $testdir
tcltest::configure -verbose {p s}

tcltest::runAllTests
tcltest::cleanupTests
