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
# Copyright 2025 Oxide Computer Company
#

#
# Common utility functions and data for I2C related tests, setup, and clean up.
#

#
# Common environment and behavior settings.
#
export LANG=C.UTF-8
export LD_PRELOAD=libumem.so
export UMEM_DEBUG=default
unalias -a
set -o errexit

#
# Access to our program.
#
I2CADM=${ISCADM:-/usr/sbin/i2cadm}

#
# List of our known controllers.
#
I2C_CTRLS=(i2csim0 smbussim1)

#
# Common exit status to use.
#
i2c_exit=0

function fatal
{
	typeset msg="$*"
	echo "TEST FAILED: $msg" >&2
	exit 1
}

function warn
{
	typeset msg="$*"
	echo "TEST FAILED: $msg" >&2
	i2c_exit=1
}

#
# Given a path, clean up all I2C devices that match that path.
#
function i2c_cleanup_path
{
	typeset path="$1"

	for dev in $(i2cadm device list -Hpo path $path | sort -r); do
		if ! i2cadm device remove $dev; then
			fatal "failed to remove $dev"
		fi
	done
}

#
# Clean up all devices that may have been created in the kernel on our simulated
# controllers.
#
function i2c_cleanup_devs
{
	for i in ${!I2C_CTRLS[*]}; do
		i2c_cleanup_path "${I2C_CTRLS[$i]}"
	done
}

function i2cadm_fail
{
	typeset ret=
	"$I2CADM" $@ 1>/dev/null 2>/dev/null
	ret=$?

	if (( ret == 0 )); then
		warn "should have failed with args $@, but passed"
	elif (( ret != 1 && ret != 2 )); then
		warn "args $@ failed with status $ret, expected 1 or 2"
	else
		printf "TEST PASSED: program failed (exited %u): %s\n" "$ret" \
		    "$*"
	fi
}

function i2cadm_pass
{
	typeset ret=
	"$I2CADM" $@ 1>/dev/null 2>/dev/null
	ret=$?
	if (( ret != 0 )); then
		warn "$@ failed with status $?, but expected success"
		return
	fi

	printf "TEST PASSED: %s ran successfully\n" "$*"
}

#
# Checks to see if the output of a command matches what we expect. This is
# expected to be used with the parseable ofmt output.
#
function i2cadm_check_output
{
	typeset exp="$1"
	typeset out=
	typeset ret=
	shift

	out=$("$I2CADM" $@ 2>/dev/null)
	ret=$?
	if (( ret != 0 )); then
		warn "$@ failed with status $ret, but expected success"
		return
	fi

	if [[ "$out" != "$exp" ]]; then
		warn "$@ had unexpected output ($out), expected: $exp"
		return
	fi

	printf "TEST PASSED: output from %s matched expected value: %s\n" "$*" \
	    "$exp"
}
