CFLAGS      ?=
CPPFLAGS    ?=
LDFLAGS     ?=
TARGET_ARCH ?=
LIBS        ?=

.PHONY: run clean monitor
run: main.tcl
	./$<
monitor: main.tcl
	ls $^ | entr ./runme.sh

.PHONY: generate_bindings
generate_bindings: tools/scapi_bind.tcl
tools/scapi_bind.tcl: tools/asn1bind.tcl asn1/Scapi.asn1 asn1/ScapiSocketClient.asn1
	tclsh $^ >$@
