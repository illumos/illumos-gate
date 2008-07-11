#!/bin/ksh -p
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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Source drop generator.
#

PATH=$(dirname $(whence $0)):$PATH
export PATH

tmpdir=$(mktemp -dt sdropXXXXX)

cleanup() {
	[ -n "$tmpdir" ] && rm -rf $tmpdir
}

fail() {
	echo $*
	cleanup
	exit 1
}

[ -n "$CODEMGR_WS" ] || fail "Please define CODEMGR_WS."
[ -n "$tmpdir" ] || fail "Can't create temp directory."

tarfile=$CODEMGR_WS/on-src.tar

cd $CODEMGR_WS
which_scm | read SCM_TYPE junk || exit 1

#
# Copy anything that's registered with source control, except for deleted files,
# into a temp directory.  Then tar that up.
#
case "$SCM_TYPE" in
mercurial)
	hg locate -X deleted_files/ | cpio -pd $tmpdir
	;;
teamware)
	find usr/src -name 's\.*' -a -type f -print | \
    	sed -e 's,SCCS\/s.,,' | \
    	grep -v '/\.del-*' | \
    	cpio -pd $tmpdir
	;;
unknown)
	fail "Unknown type of SCM in use."
	;;
*)
	fail "Unsupported SCM type: $SCM_TYPE"
	;;
esac
[ $? -eq 0 ] || fail "Couldn't populate temp directory $tmpdir."

cp README.opensolaris $tmpdir || fail "Couldn't copy README.opensolaris."

(cd $tmpdir; tar cf $tarfile .) || fail "Couldn't create $tarfile."
bzip2 -f $tarfile || fail "Couldn't bzip2 $tarfile."

cleanup
