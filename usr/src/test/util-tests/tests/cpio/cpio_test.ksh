#!/usr/bin/ksh
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
# Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
#

set -e
set -o pipefail
export LC_ALL=C

CPIO=${CPIO:-/usr/bin/cpio}
SRCDIR=$(dirname $0)
FILES=$SRCDIR/files

typeset -i failures=0

function errexit {
	echo "$@" >&2
	exit 1
}

function fail {
	echo "FAIL: $@" >&2
	((failures++))
	true
}

function pass {
	echo "PASS: $@"
}

function find_cmd {
	typeset cmd="$1"
	typeset var=$(echo $cmd | tr '[:lower:]' '[:upper:]')
	typeset -n path="$var"
	path=$(whence -fp "$cmd")
	if (($? != 0)) || [ ! -x "$path" ]; then
		errexit "Cannot find executable '$cmd' in PATH"
	fi
}

TAR=/usr/bin/tar
# This script uses a few commands which are not part of illumos and are
# expected to be available in the path.
find_cmd gtar
find_cmd stat

# Test cpio's handling of device nodes across different formats.
# To do this, we need a device file to include in the archive.

typeset -i maj
typeset -i min

# To allow this test to run without root privileges, and in a non-global zone,
# we look for a suitable device for each one. Such a device must not have a
# zero minor number and both major and minor must be small enough to fit within
# the old SVR3 types, so we restrict both to 0x7f.
if [[ $(zonename) == global ]]; then
	DEVPATH=/devices/pseudo
else
	DEVPATH=/dev
fi
DEVICE=
for device in $DEVPATH/*; do
	[[ -c "$device" ]] || continue
	set -- $($STAT -c '%Hr %Lr' $device)
	maj=$1; min=$2
	((maj == 0 || min == 0)) && continue
	((maj > 0x7f || min > 0x7f)) && continue
	DEVICE="$device"
	break
done
[[ -z $DEVICE ]] && errexit "No suitable device node found for test"

typeset expect_cpio=$(printf "%d,%3d" $maj $min)
typeset expect_gtar=$(printf "%d,%d" $maj $min)

echo "Using device $DEVICE (major=$maj/minor=$min) as test subject"

stderr=$(mktemp)
[ -f "$stderr" ] || errexit "Could not create temporary file"
trap 'rm -f $stderr' EXIT
function reset_err
{
	:>$stderr
	exec 4>$stderr
}

# Create archives using tar and check that cpio can extract them.

reset_err
if { $TAR cf - $FILES 2>&4 | $CPIO -qH ustar -it 2>&4; } >/dev/null; then
	pass "tar->cpio(files)"
else
	fail "tar->cpio(files) $@ [$(<$stderr)]"
fi

# Check that the major/minor of the device node are correctly transferred
set -- $($TAR cf - $DEVICE 2>&4 | $CPIO -qH ustar -ivt 2>&4)
if echo "$@" | egrep -s "$expect_cpio"; then
	pass "tar->cpio()"
else
	fail "tar->cpio() $@ [$(<$stderr)]"
fi

# Create archives using GNU tar and check that cpio correctly extracts the
# device nodes.

for f in posix ustar; do
	reset_err
	if { $GTAR --format=$f -cf - $FILES 2>&4 | \
	    $CPIO -qH ustar -it 2>&4; } >/dev/null; then
		pass "gtar->cpio(files:$f)"
	else
		fail "gtar->cpio(files:$f) $@ [$(<$stderr)]"
	fi

	# Check that the major/minor of the device node are correctly
	# transferred
	reset_err
	set -- $($GTAR --format=$f -cf - $DEVICE 2>&4 | \
	    $CPIO -qH ustar -ivt 2>&4 | grep ${DEVICE#/})
	if echo "$@" | egrep -s "$expect_cpio"; then
		pass "gtar->cpio($f)"
	else
		fail "gtar->cpio($f) $@ [$(<$stderr)]"
	fi
done

# Now the inverse, create the archives using cpio and confirm that GNU tar
# can extract them.

for f in tar ustar; do
	reset_err
	if { find $FILES | $CPIO -qH $f -o 2>&4 | \
	    $GTAR tvf - 2>&4; } >/dev/null; then
		pass "cpio->gtar(files:$f)"
	else
		fail "cpio->gtar(files:$f) $@ [$(<$stderr)]"
	fi

	# Check that the major/minor of the device node are correctly
	# transferred.
	reset_err
	set -- $(echo $DEVICE | $CPIO -qH $f -o 2>&4 | $GTAR tvf - 2>&4)
	if echo "$@" | egrep -s "$expect_gtar"; then
		pass "cpio->gtar($f)"
	else
		fail "cpio->gtar($f) $@ [$(<$stderr)]"
	fi
done

# Test extracting cpio-generated archives with cpio.

for f in crc odc odc_sparse ascii_sparse ustar; do
	reset_err
	if { find $FILES | $CPIO -qH $f -o 2>&4 | \
	    $CPIO -qH $f -ivt 2>&4; } >/dev/null; then
		pass "cpio->cpio(files:$f)"
	else
		fail "cpio->cpio(files:$f) $@ [$(<$stderr)]"
	fi

	# Check that the major/minor of the device node are correctly
	# transferred
	reset_err
	set -- $(echo $DEVICE | $CPIO -qH $f -o 2>&4 | \
	    $CPIO -qH $f -ivt 2>&4 | grep ${DEVICE#/})
	if echo "$@" | egrep -s "$expect_cpio"; then
		pass "cpio->cpio($f)"
	else
		fail "cpio->cpio($f) $@ [$(<$stderr)]"
	fi
done

# And a cpio archive with no format specified.

reset_err
if { find $FILES | $CPIO -qo 2>&4 | $CPIO -qivt 2>&4; } >/dev/null; then
	pass "cpio->cpio(files:native)"
else
	fail "cpio->cpio(files:native) $@ [$(<$stderr)]"
fi

reset_err
set -- $(echo $DEVICE | $CPIO -qo 2>&4 | $CPIO -qivt 2>&4 | grep ${DEVICE#/})
if echo "$@" | egrep -s "$expect_cpio"; then
	pass "cpio->cpio(native)"
else
	fail "cpio->cpio(native) $@ [$(<$stderr)]"
fi

# Test extracting cpio samples created on FreeBSD.
# These all have maj/min 13/17 in them.

expect_cpio=$(printf "%d,%3d" 13 17)
for f in $FILES/freebsd.*.cpio; do
	reset_err
	format=${f%.*}
	format=${format##*.}
	[[ $format == pax || $format == ustar ]] && flags="-H ustar" || flags=
	set -- $($CPIO -q $flags -ivt < $f 2>&4 | grep node | grep -v Pax)
	if echo "$@" | egrep -s "$expect_cpio"; then
		pass "freebsd->cpio($format)"
	else
		fail "freebsd->cpio($format) $@ [$(<$stderr)]"
	fi
done

# This is a 'bar' file created on a SunOS 4.x system. It contains a
# /dev/zero device node with major/minor 3/12

reset_err
expect_cpio=$(printf "%d,%3d" 3 12)

set -- $($CPIO -qH bar -ivt < $FILES/zero.bar 2>&4 | grep test/zero | head -1)
if echo "$@" | egrep -s "$expect_cpio"; then
	pass "sunos->cpio(bar)"
else
	fail "sunos->cpio(bar) $@ [$(<$stderr)]"
fi

exit $FAILURES

