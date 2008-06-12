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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Create an encumbered binaries tarball from a full build proto area,
# less the contents of an OpenSolaris proto area.  Special handling
# for crypto binaries that need to be signed by Sun Release
# Engineering.
#

usage="bindrop [-n] full-root open-root basename"

isa=`uname -p`
if [[ "$isa" = sparc ]]; then
	isa_short=s
else
	isa_short=x
fi

#
# Crypto related binaries need to be signed in order to be loaded.
# We pull the ongk signed binaries from the gate machine's build
# at the path below so that the closed-bins tarballs are kept in sync
# with what we're actually delivering.  We default to pulling out of
# nightly, but if CRYPTO_BINS_PATH is set, then we pull from that path
# instead.  This allows us to override with something like
# /ws/onnv-gate/packages/$isa/snv_XX instead.
#
gatepkgs=${CRYPTO_BINS_PATH:-"/ws/onnv-gate/packages/$isa/nightly"}

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
	gatepkgs="$gatepkgs-nd"
fi

[[ -d "$gatepkgs" ]] || fail "can't find gate's crypto packages ($gatepkgs)."
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
	usr/include/sys/lo.h
	usr/include/sys/tidg.h
	usr/include/sys/tivc.h
	usr/include/sys/tmux.h
	usr/kernel/drv/amd64/lo
	usr/kernel/drv/amd64/tidg
	usr/kernel/drv/amd64/tivc
	usr/kernel/drv/amd64/tmux
	usr/kernel/drv/lo
	usr/kernel/drv/lo.conf
	usr/kernel/drv/sparcv9/lo
	usr/kernel/drv/sparcv9/tidg
	usr/kernel/drv/sparcv9/tivc
	usr/kernel/drv/sparcv9/tmux
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
	etc/smartcard/
	kernel/drv/amd64/audioens
	kernel/drv/amd64/bmc
	kernel/drv/amd64/pcn
	kernel/drv/audioens
	kernel/drv/audioens.conf
	kernel/drv/bmc
	kernel/drv/bmc.conf
	kernel/drv/ifp.conf
	kernel/drv/pcn
	kernel/drv/pcn.conf
	kernel/drv/sparcv9/audioens
	kernel/drv/sparcv9/ifp
	kernel/drv/sparcv9/isp
	kernel/drv/spwr
	kernel/drv/spwr.conf
	kernel/kmdb/sparcv9/isp
	kernel/misc/amd64/phx
	kernel/misc/phx
	kernel/misc/sparcv9/phx
	platform/SUNW,Sun-Blade-100/kernel/drv/grppm.conf
	platform/SUNW,Sun-Blade-100/kernel/drv/sparcv9/grfans
	platform/SUNW,Sun-Blade-100/kernel/drv/sparcv9/grppm
	platform/sun4u/kernel/misc/sparcv9/i2c_svc
	usr/bin/ksh
	usr/bin/pfksh
	usr/bin/rksh
	usr/bin/smartcard
	usr/ccs/bin/dis
	usr/include/smartcard/
	usr/include/sys/audio/audioens.h
	usr/include/sys/phx.h
	usr/include/sys/scsi/adapters/ifpcmd.h
	usr/include/sys/scsi/adapters/ifpio.h
	usr/include/sys/scsi/adapters/ifpmail.h
	usr/include/sys/scsi/adapters/ifpreg.h
	usr/include/sys/scsi/adapters/ifpvar.h
	usr/include/sys/scsi/adapters/ispcmd.h
	usr/include/sys/scsi/adapters/ispmail.h
	usr/include/sys/scsi/adapters/ispreg.h
	usr/include/sys/scsi/adapters/ispvar.h
	usr/lib/amd64/libsmartcard.so.1
	usr/lib/amd64/libsmartcard.so
	usr/lib/amd64/llib-lsmartcard.ln
	usr/lib/libsmartcard.so.1
	usr/lib/libsmartcard.so
	usr/lib/llib-lsmartcard.ln
	usr/lib/llib-lsmartcard
	usr/lib/locale/C/LC_MESSAGES/libsmartcard.msg
	usr/lib/mdb/disasm/sparc.so
	usr/lib/mdb/disasm/sparcv9/sparc.so
	usr/lib/mdb/kvm/sparcv9/isp.so
	usr/lib/security/amd64/pam_smartcard.so.1
	usr/lib/security/amd64/pam_smartcard.so
	usr/lib/security/pam_smartcard.so.1
	usr/lib/security/pam_smartcard.so
	usr/lib/security/sparcv9/pam_smartcard.so.1
	usr/lib/security/sparcv9/pam_smartcard.so
	usr/lib/smartcard/
	usr/lib/sparcv9/libsmartcard.so.1
	usr/lib/sparcv9/libsmartcard.so
	usr/lib/sparcv9/llib-lsmartcard.ln
	usr/platform/SUNW,Netra-T12/
	usr/platform/sun4u/include/sys/i2c/misc/i2c_svc.h
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
	usr/sbin/ocfserv
	usr/share/javadoc/smartcard/
	usr/share/lib/smartcard/
	usr/share/lib/sgml/locale/C/dtds/docbook/docbook.dtd
	usr/share/lib/sgml/locale/C/dtds/docbook/
	usr/share/lib/sgml/locale/C/dtds/solbookv1/solbook.dtd
	usr/share/lib/sgml/locale/C/dtds/solbookv1/
	var/svc/manifest/network/rpc/ocfserv.xml
"
# memory fault injector test framework
delete="$delete
	usr/bin/mtst
	platform/sun4u/kernel/drv/sparcv9/memtest
	platform/sun4u/kernel/drv/memtest.conf
	platform/sun4v/kernel/drv/sparcv9/memtest
	platform/sun4v/kernel/drv/memtest.conf
	platform/i86pc/kernel/drv/memtest.conf
	platform/i86pc/kernel/drv/memtest
	platform/i86pc/kernel/drv/amd64/memtest
	usr/platform/i86pc/lib/mtst/mtst_AuthenticAMD_15.so
"
# pci test tool
delete="$delete
	usr/share/man/man1m/pcitool.1m
	usr/sbin/pcitool
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
(cd "$tmpdir/closed/$rootdir"; find . -name \*.h -exec rm -f {} \;)

#
# Remove empty directories that the open tree doesn't need.
#
# Step 1: walk the usr/src/pkgdefs files to find out which directories
# are specified in the open packages; save that list to a temporary
# file $needdirs.
#
(cd "$SRC/pkgdefs"; \
	find . -name prototype\* -exec grep "^d" {} \; | awk '{print $3}' > \
	"$needdirs")
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
# Replace the crypto binaries with ones that have been signed by ongk.
# Get these from onnv-gate's nightly build
#

# List of files to copy, in the form "pkgname file [file ...]"
# common files
cfiles="
	SUNWcsl
	usr/lib/security/pkcs11_kernel.so.1
	usr/lib/security/pkcs11_softtoken.so.1
"
# sparc-only
csfiles="
	SUNWcakr.u
	platform/sun4u-us3/kernel/crypto/sparcv9/aes
	platform/sun4u/kernel/crypto/sparcv9/arcfour
	platform/sun4u/kernel/crypto/sparcv9/des
	SUNWcakr.v
	platform/sun4v/kernel/drv/sparcv9/ncp
	SUNWckr
	kernel/crypto/sparcv9/aes
	kernel/crypto/sparcv9/arcfour
	kernel/crypto/sparcv9/blowfish
	kernel/crypto/sparcv9/des
	SUNWcsl
	usr/lib/security/sparcv9/pkcs11_kernel.so.1
	usr/lib/security/sparcv9/pkcs11_softtoken.so.1
	SUNWdcar
	kernel/drv/sparcv9/dca
	SUNWn2cp.v
	platform/sun4v/kernel/drv/sparcv9/n2cp
"
# x86-only
cxfiles="
	SUNWckr
	kernel/crypto/aes
	kernel/crypto/arcfour
	kernel/crypto/blowfish
	kernel/crypto/des
	kernel/crypto/amd64/aes
	kernel/crypto/amd64/arcfour
	kernel/crypto/amd64/blowfish
	kernel/crypto/amd64/des
	SUNWcsl
	usr/lib/security/amd64/pkcs11_kernel.so.1
	usr/lib/security/amd64/pkcs11_softtoken.so.1
	SUNWdcar
	kernel/drv/dca
	kernel/drv/amd64/dca
"
# These all have hard links from crypto/foo to misc/foo.
linkedfiles="
	platform/sun4u/kernel/crypto/sparcv9/des
	kernel/crypto/des
	kernel/crypto/amd64/des
	kernel/crypto/sparcv9/des
"

if [[ "$isa" = sparc ]]; then
	cfiles="$cfiles $csfiles"
else
	cfiles="$cfiles $cxfiles"
fi

# Copy $pkgfiles from the gate's build for $pkg
function pkgextract
{
	[[ -d "$gatepkgs/$pkg" ]] || fail "$gatepkgs/$pkg doesn't exist."
	if [[ -n "$pkg" && -n "$pkgfiles" ]]; then
		(cd "$gatepkgs/$pkg/reloc" && tar cf - $pkgfiles) | \
			(cd "$tmpdir/closed/$rootdir"; tar xf - )
		# Doesn't look like we can rely on $? here.
		for f in $pkgfiles; do
			[[ -f "$tmpdir/closed/$rootdir/$f" ]] || 
				warn "couldn't find $f in $gatepkgs/$pkg"
		done
	fi
}

pkg=""
pkgfiles=""
for cf in $cfiles; do
	if [[ "$cf" = SUNW* ]]; then
		pkgextract
		pkg="$cf"
		pkgfiles=""
		continue
	else
		pkgfiles="$pkgfiles $cf"
	fi
done
pkgextract			# last package in $cfiles

# Patch up the crypto hard links.
for f in $linkedfiles; do
	[[ -f "$tmpdir/closed/$rootdir/$f" ]] || continue
	link=$(print $f | sed -e s=crypto=misc=)
	(cd "$tmpdir/closed/$rootdir"; rm "$link"; ln "$f" "$link")
done

#
# Add binary license files.
#

cp -p "$SRC/tools/opensolaris/BINARYLICENSE.txt" "$tmpdir/closed" || \
    fail "can't add BINARYLICENSE.txt"
mkreadme "$tmpdir/closed"
cp -p "$CODEMGR_WS/THIRDPARTYLICENSE.ON-BINARIES" "$tmpdir/closed" || \
    fail "can't add THIRDPARTYLICENSE.ON-BINARIES."

(cd "$tmpdir"; tar cf "$tarfile" closed) || fail "can't create $tarfile."
bzip2 -f "$tarfile" || fail "can't compress $tarfile".

rm -rf "$tmpdir"

exit 0
