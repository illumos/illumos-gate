#! /usr/bin/sh
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

prog=$0
pd=`dirname $prog`
MACH=`uname -p`
elfcmp=$pd/elfcmp
elfsign=$pd/$MACH/elfsign

aopt=
copt=
eopt=
Fopt=
kopt=
vopt=

Usage() {
	echo "Usage: $prog {sign|verify} [-v] [-a]" \
		"[-c <cert>] [-k <key>] [-F <format>] -e <elf>" 1>&2
	exit 1
}

if [ $# -lt 1 ]; then
	Usage
	fi
cmd=$1
shift

while getopts "ac:e:F:k:v" opt ; do
	case $opt in
	a)	aopt=-a;;
	c)	copt="$OPTARG";;
	e)	eopt="$OPTARG";;
	F)	Fopt="$OPTARG";;
	k)	kopt="$OPTARG";;
	v)	vopt=-v;;
	\?)	Usage;;
	esac
done

case X$eopt in X) Usage;; esac

tmpe=$eopt.e$$
tmpo=$eopt.o$$

cpq() {
	cp -p $1 $2 > /dev/null 2>&1
}

restore() {
	cpq $tmpe $eopt
}

cleanup() {
	restore
	rm -f $tmpe $tmpo
}

trap cleanup 1 2 3 13 15

cpq $eopt $tmpe

eval $elfsign $cmd $aopt $vopt ${copt:+-c} ${copt} ${kopt:+-k} ${kopt} \
	${Fopt:+-F} ${Fopt} -e ${eopt}
rv=$?

case $cmd:$rv in
sign:0)
	if $elfcmp -v -S $tmpe $eopt > $tmpo 2>&1
	then
		: # all's fine
	else
		rv=$?
		echo "Warning: elfcmp failed: $eopt" 1>&2
		cat ${tmpo} 1>&2
		echo "current directory: `pwd`" 1>&2
		restore
		cpq ${eopt} ${eopt}.elfcmp.failed.$$
	fi
	;;
sign:*)
	restore
	cpq ${eopt} ${eopt}.elfsign.failed.$$
	;;
esac

rm -f $tmpe $tmpo
exit $rv
