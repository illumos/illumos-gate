#! /usr/bin/ksh -p
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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

#
# Wrap up a set of BFU archives as a tarball, including binary license
# files.
# usage: bfudrop build-id
# where "build-id" is the build identifier in the archives directory
# of the current workspace (e.g., "nightly").
#

usage="bfudrop build-id"

fail() {
	echo $*
	exit 1
}

[ -n "$SRC" ] || fail "Please set SRC."
[ -n "$CODEMGR_WS" ] || fail "Please set CODEMGR_WS."

#
# Directory that we assemble everything in.  Everything goes into
# $subdir so that it unpacks cleanly.
#
stagedir=$(mktemp -dt bfudropXXXXX)

[ -n "$stagedir" ] || fail "Can't create staging directory."

scratchdir=$stagedir/tmp

#
# Generate README.BFU-ARCHIVES.$isa from boilerplate and the contents
# of the bfu archives.
# usage: cd archivedir; mkreadme destdir
#
mkreadme() {
	destdir=$1
	readme=$destdir/README.BFU-ARCHIVES.$isa
	sed -e s/@ISA@/$isa/ -e s/@DELIVERY@/BFU-ARCHIVES/ \
	    $SRC/tools/opensolaris/README.binaries.tmpl > $readme
	for f in *; do
		echo "==== $f ====" >> $readme
		#
		# The cpio table of contents includes directories, and
		# we just want files.  So unpack the cpio file into a
		# temp directory, do a find(1) to get the table of
		# contents, and remove the temp directory.
		#
		mkdir -p $scratchdir || fail "can't create $scratchdir."
		case $f in
		*.gz)	cat=gzcat;;
		*.Z|*.bz2)
			fail "$f: compression type not supported"
			;;
		*)	cat=cat;;
		esac
		$cat $f | (cd $scratchdir; cpio -id)
		if [ $? -ne 0 ]; then
			fail "can't extract $f"
		fi
		(cd $scratchdir; find * -type f -print) | sort >> $readme
		rm -rf $scratchdir
	done
}

if [ $# -ne 1 ]; then
	fail "usage: $usage"
fi
build=$1
subdir="archives-$build"

isa=`uname -p`
tarfile=$CODEMGR_WS/on-bfu-$build.$isa.tar

mkdir -p $stagedir/$subdir/$isa || \
    fail "Can't create $stagedir/$subdir/$isa."

cd $CODEMGR_WS

archvdir=archives/$isa/$build
[ -d $archvdir ] || fail "Can't find $archvdir."

# copy archives
(cd $archvdir; tar cf - .) | (cd $stagedir/$subdir/$isa; tar xf -)

# Insert binary license files.
cp -p $SRC/tools/opensolaris/BINARYLICENSE.txt $stagedir/$subdir || \
    fail "Can't add BINARYLICENSE.txt"
(cd $archvdir; mkreadme $stagedir/$subdir)
cp -p $CODEMGR_WS/THIRDPARTYLICENSE.BFU-ARCHIVES $stagedir/$subdir || \
    fail "Can't add THIRDPARTYLICENSE.BFU-ARCHIVES."

(cd $stagedir; tar cf $tarfile $subdir) || fail "Can't create $tarfile."
bzip2 -f $tarfile || fail "Can't compress $tarfile".

rm -rf $stagedir
