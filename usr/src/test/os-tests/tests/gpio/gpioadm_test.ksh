#!/usr/bin/ksh
#
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2022 Oxide Computer Company
#

#
# Set up the environment with a standard locale and debugging tools to
# help us catch failures.
#
export LC_ALL=C.UTF-8
export LD_PRELOAD=libumem.so
export UMEM_DEBUG=default
unalias -a
set -o pipefail

gt_prog=/usr/sbin/gpioadm
gt_arg0=$(basename $0)
gt_data="$(dirname $0)/data"
gt_exit=0
gt_tmpfile="/tmp/gpioadm_test.$$"
gt_dpio0="gpioadmtestsim00"
gt_dpio1="gpioadmtestsim10"
gt_dpio2="gpioadmtestsim21"

warn()
{
        typeset msg="$*"
        [[ -z "$msg" ]] && msg="failed"
        echo "TEST FAILED: $msg" >&2
	gt_exit=1
}

fatal()
{
        typeset msg="$*"
        [[ -z "$msg" ]] && msg="failed"
        echo "$sc_arg0: $msg" >&2
        exit 1
}

cleanup()
{
	rm -f "$gt_tmpfile"
}

#
# This is an invocation of gpioadm that we want to verify runs
# successfully. We do not care about it's output, only that it exits 0.
#
expect_success()
{
	if ! $gt_prog $@ >/dev/null; then
		warn "failed to run $@"
	fi
}

#
# This is an invocation of gpioadm that we want to verify exits
# non-zero. We do not care if it is a failure or due to usage.
#
gpioadm_err()
{
	typeset reason="$1"
	shift

	if $gt_prog $@ 2>/dev/null 1>/dev/null; then
		warn "should have failed with args "$@", but passed"
		return
	fi

	printf "TEST PASSED: $reason: %s\n" "$*"
}

#
# This is a case where we expect gpioadm to exit sucessfully, but we
# want to check its exit data against a known value.
#
check_output()
{
	typeset outfile="$gt_data/$1"
	shift

	if ! $gt_prog $@ > $gt_tmpfile 2>&1; then
		warn "$@: exited non-zero"
	fi

	if ! diff $outfile $gt_tmpfile; then
		warn "$@: output mismatched"
	else
		printf "TEST PASSED: %s\n" "$*"
	fi
}

check_dpio_link()
{
	typeset dpio="$1"

	if [[ ! -L "/dev/dpio/$dpio" ]]; then
		warn "missing /dev link for $dpio"
	else
		printf "TEST PASSED /dev link for %s present\n" "$dpio"
	fi
}

#
# This gets a specific GPIO's attribute value and confirm it's what we
# expect.
#
check_attr_field()
{
	typeset gpio="$1"
	typeset attr="$2"
	typeset exp="$3"
	typeset field="$4"
	typeset out=

	out=$($gt_prog gpio attr get -p -o $field $gpio $attr)
	if (( $? != 0 )); then
		warn "failed to gpio attr get $gpio $attr"
		return
	fi

	if [[ "$out" != "$exp" ]]; then
		warn "$gpio $attr has $field $out, expected $exp"
	else
		printf "TEST PASSED: %s %s has expected %s %s\n" "$gpio" \
		    "$attr" "$field" "$exp"
	fi
}

check_attr_val()
{
	check_attr_field $1 $2 $3 "value"
}

if [[ -n $GPIOADM ]]; then
	gt_prog=$GPIOADM
fi

trap 'cleanup' EXIT

#
# These are a series of programs we expect to fail due to invalid
# arguments and other variants that don't require state to be built up.
# These are all basically bad flags, commands, or filters that don't
# match. Other tests in the gpio test suite will go and verify the more
# fine grained errors against libxpio directly.
#
gpioadm_err "bad command" foo
gpioadm_err "bad command" foo bar
gpioadm_err "incomplete command" controller
gpioadm_err "bad command" controller nope
gpioadm_err "bad command" controller wry
gpioadm_err "bad flags" controller list -b
gpioadm_err "parse without fields" controller list -p
gpioadm_err "bad field" controller list -p -o itsatrap
gpioadm_err "bad field" controller list -o itsatrap
gpioadm_err "bad field" controller list -p -o controller,itsatrap
gpioadm_err "unmatched filter" controller list this/doesnt/exist
gpioadm_err "incomplete command" gpio
gpioadm_err "bad command" gpio celes
gpioadm_err "bad command" gpio celes terra
gpioadm_err "bad flags" gpio list -r
gpioadm_err "bad flags" gpio list -7
gpioadm_err "parse without fields" gpio list -p
gpioadm_err "bad field" gpio list -p -o 12345
gpioadm_err "bad field" gpio list -o 12345
gpioadm_err "bad field" gpio list -p -o name,12345
gpioadm_err "unmatched filter" gpio list life/hopes/dreams
gpioadm_err "unmatched filter" gpio list where do they come from
gpioadm_err "match more than one with -1" gpio list -1
gpioadm_err "match more than one with -1" gpio list -1 gpio_sim0
gpioadm_err "match more than one with -1" gpio list -1 gpio_sim0 gpio_sim1
gpioadm_err "match more than one with -1" gpio list -1 */open-drain
gpioadm_err "match more than one with -1" gpio list -1 \
    gpio_sim0/periodic-500ms gpio_sim1/1v8
gpioadm_err "incomplete command" gpio attr
gpioadm_err "bad command" gpio attr where are they going
gpioadm_err "missing controller/gpio" gpio attr get
gpioadm_err "bad controller/gpio" gpio attr get null
gpioadm_err "bad controller/gpio" gpio attr get gpio_sim/3
gpioadm_err "bad controller/gpio" gpio attr get gpio_sim0/kefka
gpioadm_err "parse without fields" gpio attr get gpio_sim0/3 -p
gpioadm_err "bad flags" gpio attr get -p gpio_sim0/3
gpioadm_err "bad flags" gpio attr get -x gpio_sim0/3
gpioadm_err "bad fields" gpio attr get -p -o frodo gpio_sim1/2
gpioadm_err "bad fields" gpio attr get -o sam gpio_sim1/2
gpioadm_err "bad fields" gpio attr get -p -o sim:input,frodo gpio_sim1/2
gpioadm_err "bad filter" gpio attr get gpio_sim0/3 dusk
gpioadm_err "bad filter" gpio attr get gpio_sim0/3 sim:pull muysterious
gpioadm_err "missing controller/gpio" gpio attr set
gpioadm_err "bad controller/gpio" gpio attr set gandalf
gpioadm_err "bad controller/gpio" gpio attr set gpio_sim/1
gpioadm_err "bad controller/gpio" gpio attr set gpio_sim0/gimli
gpioadm_err "missing attributes" gpio attr set gpio_sim0/1
gpioadm_err "bad flags" gpio attr set -x gpio_sim0/4 sim:output=low
gpioadm_err "bad attribute string" gpio attr set gpio_sim0/1 foo
gpioadm_err "bad attribute string" gpio attr set gpio_sim0/1 foo=
gpioadm_err "bad attribute value" gpio attr set gpio_sim0/1 sim:speed=random
gpioadm_err "bad attribute value" gpio attr set gpio_sim0/1 sim:input=0x42
gpioadm_err "incomplete command" dpio
gpioadm_err "bad command" dpio alchemy
gpioadm_err "bad flags" dpio list -m
gpioadm_err "parse without fields" dpio list -p
gpioadm_err "bad field" dpio list -p -o sabin
gpioadm_err "bad field" dpio list -o edgar
gpioadm_err "bad field" dpio list -p -o edgar,sabin,controller
gpioadm_err "unmatched filter" dpio list locke/esper
gpioadm_err "missing operands" dpio define
gpioadm_err "missing dpio" dpio define cloud
gpioadm_err "missing dpio" dpio define tifa/
gpioadm_err "missing dpio" dpio define sepiroth/7
gpioadm_err "bad controller" dpio define cloud buster
gpioadm_err "bad controller" dpio define tifa/ 7th
gpioadm_err "bad controller" dpio define sepiroth/7 reunion
gpioadm_err "bad controller" dpio define rufus/8 hq
gpioadm_err "bad flags" dpio define -7 rufus/8 hq
gpioadm_err "missing controller/gpio" dpio undefine
gpioadm_err "bad controller/gpio" dpio undefine red13/
gpioadm_err "bad controller/gpio" dpio undefine cid/2
gpioadm_err "bad dpio name" dpio define gpio_sim/1 '-trap'
gpioadm_err "bad dpio name" dpio define gpio_sim/1 '+foobar'
gpioadm_err "bad dpio name" dpio define gpio_sim/1 '$nope'
gpioadm_err "bad dpio name" dpio define gpio_sim/1 '~sorry'
gpioadm_err "bad dpio name" dpio define gpio_sim/1 \
    'thisisanamethatisactuallytoolongibelieve'
gpioadm_err "bad dpio name" dpio define gpio_sim/1 'unsup()12#d'

#
# For the next set of tests we verify expected output from the various
# listing operations with the goal of verifying that field selection,
# parseability, omitting the header, and filtering is all working. Note,
# we explicitly never use an unfiltered top-level list operation as we
# have to assume that there will be something else on the system other
# than the gpio_sim controllers that we create.
#
check_output "ctrl-list.out" controller list -o \
    controller,ngpios,ndpios,provider,path gpio_sim0 gpio_sim1 gpio_sim2
check_output "ctrl-list-H.out" controller list -H -o \
    controller,ngpios,ndpios,provider,path gpio_sim0 gpio_sim1 gpio_sim2
check_output "ctrl-list-p.out" controller list -p -o \
    controller,ngpios,ndpios,provider,path gpio_sim0 gpio_sim1 gpio_sim2
check_output "ctrl-list-sim1.out" controller list -o \
    controller,ngpios,provider gpio_sim1
check_output "ctrl-list-H-sim1.out" controller list -H -o \
    controller,ngpios,provider gpio_sim1
check_output "ctrl-list-p-sim1.out" controller list -p -o \
    controller,ngpios,provider gpio_sim1
check_output "gpio-period500.out" gpio list */periodic-500ms
check_output "gpio-period500-H.out" gpio list -H */periodic-500ms
check_output "gpio-period500-o.out" gpio list -o controller */periodic-500ms
check_output "gpio-period500-p.out" gpio list -p -o controller */periodic-500ms
check_output "gpio-sim0.out" gpio list gpio_sim0
check_output "gpio-sim0-H.out" gpio list -H gpio_sim0
check_output "gpio-sim0-o.out" gpio list -o controller gpio_sim0
check_output "gpio-sim0-p.out" gpio list -p -o controller gpio_sim0
check_output "gpio-sim01.out" gpio list gpio_sim0 gpio_sim1
check_output "gpio-sim01-H.out" gpio list -H gpio_sim0 gpio_sim1
check_output "gpio-sim01-o.out" gpio list -o controller gpio_sim0 gpio_sim1
check_output "gpio-sim01-p.out" gpio list -p -o controller gpio_sim0 gpio_sim1
check_output "attr-g0_0.out" gpio attr get gpio_sim0/0
check_output "attr-g0_0-H.out" gpio attr get -H gpio_sim0/0
check_output "attr-g0_0-o.out" gpio attr get -o attr,value,raw,possible \
    gpio_sim0/0
check_output "attr-g0_0-Ho.out" gpio attr get -H -o attr,value,raw,possible \
    gpio_sim0/0
check_output "attr-g0_0-p.out" gpio attr get -p -o attr,value,raw,possible \
    gpio_sim0/0
check_output "attr-g0_0_filt.out" gpio attr get -o attr,value gpio_sim0/0 \
    name sim:pull sim:voltage
check_output "attr-g0_0_filt-p.out" gpio attr get -p -o attr,value gpio_sim0/0 \
    name sim:pull sim:voltage
#
# Repeat the above with the actual GPIO name
#
check_output "attr-g0_0.out" gpio attr get gpio_sim0/1v8
check_output "attr-g0_0-H.out" gpio attr get -H gpio_sim0/1v8
check_output "attr-g0_0-o.out" gpio attr get -o attr,value,raw,possible \
    gpio_sim0/1v8
check_output "attr-g0_0-Ho.out" gpio attr get -H -o attr,value,raw,possible \
    gpio_sim0/1v8
check_output "attr-g0_0-p.out" gpio attr get -p -o attr,value,raw,possible \
    gpio_sim0/1v8
check_output "attr-g0_0_filt.out" gpio attr get -o attr,value gpio_sim0/1v8 \
    name sim:pull sim:voltage
check_output "attr-g0_0_filt-p.out" gpio attr get -p -o attr,value \
    gpio_sim0/1v8 name sim:pull sim:voltage

#
# To test DPIOs listing we need to actually go through and create a few
# DPIOs. However, we also need to make sure that we leave the test with
# these destroyed so we don't interfere with any other tests.
#
expect_success dpio define gpio_sim0/0 "$gt_dpio0"
expect_success dpio define -r -w gpio_sim1/0 "$gt_dpio1"
expect_success dpio define -r -K gpio_sim2/3v3 "$gt_dpio2"

check_output "ctrl-list-dpio-p.out" controller list -p -o controller,ndpios \
    gpio_sim0 gpio_sim1 gpio_sim2

check_output "dpio.out" dpio list "$gt_dpio0" "$gt_dpio1" "$gt_dpio2"
check_output "dpio-H.out" dpio list -H "$gt_dpio0" "$gt_dpio1" "$gt_dpio2"
check_output "dpio-o.out" dpio list -o dpio,caps,flags,controller,gpionum \
    "$gt_dpio0" "$gt_dpio1" "$gt_dpio2"
check_output "dpio-Ho.out" dpio list -H -o dpio,caps,flags,controller,gpionum \
    "$gt_dpio0" "$gt_dpio1" "$gt_dpio2"
check_output "dpio-p.out" dpio list -p -o dpio,caps,flags,controller,gpionum \
    "$gt_dpio0" "$gt_dpio1" "$gt_dpio2"

#
# Make sure the symlinks are installed correctly
#
check_dpio_link "$gt_dpio0"
check_dpio_link "$gt_dpio1"
check_dpio_link "$gt_dpio2"

expect_success dpio undefine gpio_sim0/0
expect_success dpio undefine gpio_sim1/0
expect_success dpio undefine gpio_sim2/3v3

#
# Different gpio_sim gpios have different possible values and different
# defaults. Make sure that we actually see different possible values for
# the same attribute on different gpios and that it's not all the same.
# Mix up the use of IDs and names.
#
check_attr_val gpio_sim1/1 name 3v3
check_attr_val gpio_sim1/5 name open-drain
check_attr_field gpio_sim1/3v3 sim:voltage 3.3V possible
check_attr_field gpio_sim1/2 sim:voltage 12.0V possible
check_attr_field gpio_sim1/open-drain sim:voltage 1.8V possible
check_attr_field gpio_sim1/3 sim:pull disabled,23k-down,5k-up,40k-up possible
check_attr_field gpio_sim1/0 sim:output disabled,low,high possible
check_attr_field gpio_sim1/5 sim:output disabled,low possible
check_attr_field gpio_sim1/5 sim:pull "disabled,down,up,up|down" possible

#
# Change around a few gpio sim attributes to make sure basic attribute
# maniuplation works and then change them back.
#
check_attr_val gpio_sim0/3 sim:output low
check_attr_val gpio_sim0/3 sim:pull 23k-down
check_attr_val gpio_sim0/3 sim:input low
expect_success gpio attr set gpio_sim0/3 sim:output=disabled sim:pull=40k-up
check_attr_val gpio_sim0/3 sim:output disabled
check_attr_val gpio_sim0/3 sim:pull 40k-up
check_attr_val gpio_sim0/3 sim:input high
expect_success gpio attr set gpio_sim0/3 sim:output=low sim:pull=23k-down
check_attr_val gpio_sim0/3 sim:output low
check_attr_val gpio_sim0/3 sim:pull 23k-down
check_attr_val gpio_sim0/3 sim:input low

#
# Repeat with the name instead of the ID.
#
check_attr_val gpio_sim0/54V sim:output low
check_attr_val gpio_sim0/54V sim:pull 23k-down
check_attr_val gpio_sim0/54V sim:input low
expect_success gpio attr set gpio_sim0/54V sim:output=disabled sim:pull=40k-up
check_attr_val gpio_sim0/54V sim:output disabled
check_attr_val gpio_sim0/54V sim:pull 40k-up
check_attr_val gpio_sim0/54V sim:input high
expect_success gpio attr set gpio_sim0/54V sim:output=low sim:pull=23k-down
check_attr_val gpio_sim0/54V sim:output low
check_attr_val gpio_sim0/54V sim:pull 23k-down
check_attr_val gpio_sim0/54V sim:input low

if (( gt_exit == 0 )); then
	printf "All tests passed successfully!\n"
fi
