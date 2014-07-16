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
#

# First we set $dir to dirname $0, and $prog to basename $0 .ksh,
# using efficient ksh builtins.
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
prog=${prog%.ksh}

for a in $* 
do
	if [[ $a == "-d" ]]
	then
		debug=yes
	fi
done

# We look for architecture specific versions of the program,
# searching in several candidate directories.  We run each one as
# we find it.
for f in $(/usr/bin/isainfo)
do
	found=
	[[ -n $debug ]] && print "Checking for arch $f:"
	for p in \
		${dir}/${prog}.${f} \
		${dir}/${f}/${prog}.${f} \
		${dir}/${f}/${prog}
	do
		[[ -n $found ]] && continue
		[[ -n $debug ]] && print -n "     $p"
		if [[ -f $p ]]; then
			[[ -n $debug ]] && print " FOUND"
			[[ -n $debug ]] && print "Executing $p $*"
			found=yes
			$p $* || exit 1
		else
			[[ -n $debug ]] && print
		fi
	done
	[[ -z $found ]] && [[ -n $debug ]] && print "NOT PRESENT"
done
exit 0
