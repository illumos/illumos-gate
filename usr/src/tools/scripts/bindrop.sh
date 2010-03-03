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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Create an encumbered binaries tarball from a full build proto area,
# less the contents of an OpenSolaris proto area.  Special handling
# for crypto binaries that need to be signed by Sun Release
# Engineering.
#

usage="bindrop [-n] full-root open-root basename"

isa=`uname -p`

PATH="$PATH:/usr/bin:/usr/sfw/bin"

function fail {
	print -u2 "bindrop: $@"
	exit 1
}

function warn {
	print -u2 "bindrop: warning: $@"
}

[[ -n "$SRC" ]] || fail "SRC must be set."
[[ -n "$CODEMGR_WS" ]] || fail "CODEMGR_WS must be set."

#
# Create the README from boilerplate and the contents of the closed
# binary tree.
#
# usage: mkreadme targetdir
#
function mkreadme {
	typeset targetdir="$1"
	typeset readme="README.ON-BINARIES.$isa"

	sed -e s/@ISA@/$isa/ -e s/@DELIVERY@/ON-BINARIES/ \
	    "$SRC/tools/opensolaris/README.binaries.tmpl" > "$targetdir/$readme"
	(cd "$targetdir"; find "$rootdir" -type f -print | \
	    sort >> "$targetdir/$readme")
}

nondebug=n
while getopts n flag; do
	case $flag in
	n)
		nondebug=y
		;;
	?)
		print -u2 "usage: $usage"
		exit 1
		;;
	esac
done
shift $(($OPTIND - 1))

if [[ $# -ne 3 ]]; then
	print -u2 "usage: $usage"
	exit 1
fi

full="$1"
open="$2"
tarfile="$CODEMGR_WS/$3.$isa.tar"

rootdir="root_$isa"
if [[ "$nondebug" = y ]]; then
	rootdir="root_$isa-nd"
fi

[[ -d "$full" ]] || fail "can't find $full."
[[ -d "$open" ]] || fail "can't find $open."

tmpdir=$(mktemp -dt bindropXXXXX)
[[ -n "$tmpdir" ]] || fail "can't create temporary directory."
mkdir -p "$tmpdir/closed/$rootdir" || exit 1

#
# This will hold a temp list of directories that must be kept, even if
# empty.
#
needdirs=$(mktemp -t needdirsXXXXX)
[[ -n "$needdirs" ]] || fail "can't create temporary directory list file."

#
# Copy the full tree into a temp directory.
#
(cd "$full"; tar cf - .) | (cd "$tmpdir/closed/$rootdir"; tar xpf -)

#
# Remove internal ON crypto signing certs
#
delete="
	etc/certs/SUNWosnetSE
	etc/certs/SUNWosnetSolaris
	etc/crypto/certs/SUNWosnet
	etc/crypto/certs/SUNWosnetLimited
	etc/crypto/certs/SUNWosnetCF
	etc/crypto/certs/SUNWosnetCFLimited
	"

#
# Remove miscellaneous files that we don't want to ship.
#

# SUNWsvvs (SVVS test drivers).
delete="$delete
	usr/include/sys/svvslo.h
	usr/include/sys/tidg.h
	usr/include/sys/tivc.h
	usr/include/sys/tmux.h
	usr/kernel/drv/amd64/svvslo
	usr/kernel/drv/amd64/tidg
	usr/kernel/drv/amd64/tivc
	usr/kernel/drv/amd64/tmux
	usr/kernel/drv/sparcv9/svvslo
	usr/kernel/drv/sparcv9/tidg
	usr/kernel/drv/sparcv9/tivc
	usr/kernel/drv/sparcv9/tmux
	usr/kernel/drv/svvslo
	usr/kernel/drv/svvslo.conf
	usr/kernel/drv/tidg
	usr/kernel/drv/tidg.conf
	usr/kernel/drv/tivc
	usr/kernel/drv/tivc.conf
	usr/kernel/drv/tmux
	usr/kernel/drv/tmux.conf
	usr/kernel/strmod/amd64/lmodb
	usr/kernel/strmod/amd64/lmode
	usr/kernel/strmod/amd64/lmodr
	usr/kernel/strmod/amd64/lmodt
	usr/kernel/strmod/lmodb
	usr/kernel/strmod/lmode
	usr/kernel/strmod/lmodr
	usr/kernel/strmod/lmodt
	usr/kernel/strmod/sparcv9/lmodb
	usr/kernel/strmod/sparcv9/lmode
	usr/kernel/strmod/sparcv9/lmodr
	usr/kernel/strmod/sparcv9/lmodt
"
# encumbered binaries and associated files
delete="$delete
	kernel/drv/amd64/bmc
	kernel/drv/bmc
	kernel/drv/bmc.conf
	kernel/drv/ifp.conf
	kernel/drv/sparcv9/ifp
	kernel/drv/sparcv9/isp
	kernel/drv/sparcv9/qus
	kernel/drv/spwr
	kernel/kmdb/sparcv9/isp
	usr/has/bin/ksh
	usr/has/bin/pfksh
	usr/has/bin/rksh
	usr/include/sys/scsi/adapters/ifpcmd.h
	usr/include/sys/scsi/adapters/ifpio.h
	usr/include/sys/scsi/adapters/ifpmail.h
	usr/include/sys/scsi/adapters/ifpreg.h
	usr/include/sys/scsi/adapters/ifpvar.h
	usr/include/sys/scsi/adapters/ispcmd.h
	usr/include/sys/scsi/adapters/ispmail.h
	usr/include/sys/scsi/adapters/ispreg.h
	usr/include/sys/scsi/adapters/ispvar.h
	usr/lib/mdb/kvm/sparcv9/isp.so
	usr/platform/sun4u/include/sys/memtestio.h
	usr/platform/sun4u/include/sys/memtestio_ch.h
	usr/platform/sun4u/include/sys/memtestio_chp.h
	usr/platform/sun4u/include/sys/memtestio_ja.h
	usr/platform/sun4u/include/sys/memtestio_jg.h
	usr/platform/sun4u/include/sys/memtestio_sf.h
	usr/platform/sun4u/include/sys/memtestio_sr.h
	usr/platform/sun4u/include/sys/memtestio_u.h
	usr/platform/sun4u/include/sys/memtestio_pn.h
	usr/platform/sun4v/include/sys/memtestio.h
	usr/platform/sun4v/include/sys/memtestio_ni.h
	usr/platform/sun4v/include/sys/memtestio_v.h
"
# memory fault injector test framework
delete="$delete
	usr/bin/mtst
	platform/sun4u/kernel/drv/sparcv9/memtest
	platform/sun4u/kernel/drv/memtest.conf
	platform/sun4v/kernel/drv/sparcv9/memtest
	platform/sun4v/kernel/drv/memtest.conf
	kernel/drv/memtest.conf
	kernel/drv/memtest
	kernel/drv/amd64/memtest
	usr/platform/i86pc/lib/mtst/mtst_AuthenticAMD_15.so
	usr/platform/i86pc/lib/mtst/mtst_AuthenticAMD.so
	usr/platform/i86pc/lib/mtst/mtst_generic.so
	usr/platform/i86pc/lib/mtst/mtst_GenuineIntel.so
"
for f in $delete; do
	rm -rf "$tmpdir/closed/$rootdir/$f"
done

#
# Remove files that the open tree already has.
#
(cd "$open"; find . -type f -print -o -type l -print) > "$tmpdir/deleteme"
(cd "$tmpdir/closed/$rootdir"; cat "$tmpdir/deleteme" | xargs rm -f)

#
# Remove any header files.  If they're in the closed tree, they're
# probably not freely redistributable.
#
(cd "$tmpdir/closed/$rootdir"; find . -name \*.h \
	-a \! -name lc_core.h \
	-a \! -name localedef.h \
	-exec rm -f {} \;)


#
# Remove empty directories that the open tree doesn't need.
#
# Step 1: walk the redistributable manifests to find out which directories
# are specified in the open packages; save that list to a temporary
# file $needdirs.
#
MACH=$(uname -p)
(cd "$SRC/pkg/packages.$MACH"; \
	nawk '/^dir/ {sub(/.+ path=/, ""); print $1;}' *.metadata.*.redist | \
	sort -u > "$needdirs")

#
# Step 2: go to our closed directory, and find all the subdirectories,
# filtering out the ones needed by the open packages (saved in that
# temporary file).  Sort in reverse order, so that parent directories
# come after any subdirectories, and pipe that to rmdir.  If there are
# still any lingering files, rmdir will complain.  That's fine--we
# only want to delete empty directories--so redirect the complaints to
# /dev/null.
#
(cd "$tmpdir/closed/$rootdir"; \
	find * -type d -print | /usr/xpg4/bin/grep -xv -f $needdirs | \
	sort -r | xargs -l rmdir 2>/dev/null )

rm "$needdirs"

#
# Up above we removed the files that were already in the open tree.
# But that blew away the minimal closed binaries that are needed to do
# an open build, so restore them here.
#

mkclosed "$isa" "$full" "$tmpdir/closed/$rootdir" || \
    fail "can't restore minimal binaries."

#
# Exclude signed crypto binaries; they are delivered in their
# own tarball.
#
ROOT="$tmpdir/closed/$rootdir" findcrypto "$SRC/tools/codesign/creds" |
    awk '{ print $2 }' | (cd "$tmpdir/closed/$rootdir"; xargs rm -f)

#
# Add binary license files.
#

cp -p "$SRC/tools/opensolaris/BINARYLICENSE.txt" "$tmpdir/closed" || \
    fail "can't add BINARYLICENSE.txt"
mkreadme "$tmpdir/closed"
if [ -f "$CODEMGR_WS/THIRDPARTYLICENSE.ON-BINARIES" ]; then
    cp -p "$CODEMGR_WS/THIRDPARTYLICENSE.ON-BINARIES" "$tmpdir/closed"
fi

(cd "$tmpdir"; tar cf "$tarfile" closed) || fail "can't create $tarfile."
bzip2 -f "$tarfile" || fail "can't compress $tarfile".

rm -rf "$tmpdir"

exit 0
