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
# Copyright 2021 Toomas Soome <tsoome@me.com>
#

: "${FILEDIR:=/opt/util-tests/tests/files}"

[[ -d "$FILEDIR" ]] || fail "no files directory $FILEDIR"

typeset -i fail=0

function fail {
	echo "FAIL $@"
	((fail++))
}

function pass {
	echo "PASS $@"
}

function pkg_test {
	TD=$(mktemp -d -t)

	if [[ ! -d "$TD" ]]; then
		fail "couldn't create test directory $TD"
		return
	fi

	echo "PKG=svr4pkg" > $TD/pkginfo
	echo "NAME=\"svr4pkg test package\"" >> $TD/pkginfo
	echo "ARCH=sparc,i386" >> $TD/pkginfo
	echo "VERSION=1.0" >> $TD/pkginfo
	echo "CATEGORY=application" >> $TD/pkginfo
	echo "BASEDIR=/opt" >> $TD/pkginfo

	(cd $FILEDIR; /usr/bin/pkgproto svr4pkg) > $TD/prototype || \
	fail "pkgproto svr4pkg"
	echo "i pkginfo=$TD/pkginfo" >> $TD/prototype
	/usr/bin/pkgmk -f $TD/prototype -r $FILEDIR -d $TD || \
	fail "pkgmk svr4pkg"
	/usr/bin/pkgtrans -s $TD $TD/svr4pkg.pkg svr4pkg || \
	fail "pkgtrans to stream format"

	mkdir -p $TD/root/opt
	/usr/sbin/pkgadd -d $TD -R $TD/root svr4pkg || fail "pkgadd svr4pkg"
	/usr/bin/pkginfo -R $TD/root svr4pkg || fail "pkginfo svr4pkg"
	/usr/sbin/pkgrm -n -R $TD/root svr4pkg || fail "pkgrm svr4pkg"

	rm -rf "$TD"
}

pkg_test

(( fail > 0 )) && exit -1
exit 0
