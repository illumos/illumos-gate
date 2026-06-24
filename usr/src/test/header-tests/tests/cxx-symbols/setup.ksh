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

export STF_SUITE=/opt/header-tests

# First we set $dir to dirname $0, using efficient ksh builtins.
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

cfg=cxx-symbols/${prog%.ksh}.cfg

if [[ ! -f ${cfg} && $cfg == cxx-symbols/setup.cfg ]]
then
	# compiler check only
	cfg=-C
fi

pdir=$dir/../common
prog=cxx_symbols_test

for arg in $*
do
	if [[ $arg == "-d" ]]
	then
		debug=yes
	fi
done

# Determine which ISA widths this system supports.
isa=$(/usr/bin/isainfo)
case $isa in
amd64*)		sizes="32 64" ;;
sparcv9*)	sizes="32 64" ;;
aarch64*)	sizes="64" ;;
*)
	print "ERROR: Unknown ISA: $isa" >&2
	exit 1
	;;
esac

for m in $sizes
do
	p=${pdir}/${prog}_${m}
	[[ -n $debug ]] && print "Executing $p $* ${cfg}"
	[[ -f $p ]] || { print "ERROR: $p not found" >&2; exit 1; }
	$p $* ${cfg} || exit 1
done
exit 0
