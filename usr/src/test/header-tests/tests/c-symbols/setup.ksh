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
# Copyright 2014 Garrett D'Amore <garrett@damore.org>
# Copyright 2026 Gordon W. Ross
#

# First get $dir and $prog
case $0 in
*/*)
	dir=${0%/*}
	prog=${0##*/}
	;;
*)
	dir=.
	prog=${0}
	;;
esac

for arg in $*
do
	if [[ $arg == "-d" ]]
	then
		debug="-d"
	fi
done

if [[ -d "$dir/../../cfg/c-symbols" ]] ; then
	STF_SUITE="$dir/../.."
else
	STF_SUITE=/opt/header-tests
fi
export STF_SUITE

driver=$STF_SUITE/tests/common/symbol_test
envcfg=$STF_SUITE/cfg/c-symbols-env.cfg
symcfg=$STF_SUITE/cfg/c-symbols/${prog}.cfg

# Special handling for "setup".  Just run ... -C
if [[ $prog == setup ]]; then
	envcfg="-C"
	symcfg=
fi

# Determine which ISA widths this system supports.
isa=$(/usr/bin/isainfo)
case $isa in
amd64*)		mlist="32 64" ;;
sparcv9*)	mlist="32 64" ;;
aarch64*)	mlist="64" ;;
*)
	print "ERROR: Unknown ISA: $isa" >&2
	exit 1
	;;
esac

[[ -n $debug ]] && set -x
for m in $mlist
do
	$driver $debug --lang c -m${m} $envcfg $symcfg || exit 1
done
exit 0
