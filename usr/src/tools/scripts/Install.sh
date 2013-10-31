#!/bin/ksh
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
# Copyright (c) 1996, 2010, Oracle and/or its affiliates. All rights reserved.
#
# Author:  Jeff Bonwick
#
#	Please report any bugs to bonwick@eng.
#
# How Install works:
#
#	Install performs the following steps:
#
#	1. Get the list of modules, configuration files, and links
#	   that are desired.
#
#	2. Create the requested subset of /kernel in Install's temp space
#	   (/tmp/Install.username by default.)
#
#	3. Create a tar file (/tmp/Install.username/Install.tar) based on (3).
#
#	4. If -n was specified, exit.  If a target was specified using -T,
#	   rcp the tarfile to the target and exit.  If a target was specified
#	   using -t, rsh to the target machine and untar the tarfile in the
#	   target directory.
#
# If any of these steps fail, Install will give you an error message and,
# in most cases, suggest corrective measures.  Then, you can recover the
# install with "Install -R". (This is not required; it's just faster than
# starting from scratch.)
#
# One final comment:  Unfortunately, tar and I disagree on what
# constitutes a fatal error.  (tar -x will exit 0 even if it can't write
# anything in the current directory.)  Thus, I am reduced to grepping stderr
# for (what I consider) fatal and nonfatal error messages.  If you run into
# a situation where this doesn't behave the way you think it should (either
# an "Install failed" message after a successful install, or an "Install
# complete" message after it bombs), please let me know.

#
# The CDPATH variable causes ksh's `cd' builtin to emit messages to stdout
# under certain circumstances, which can really screw things up; unset it.
#
unset CDPATH

INSTALL=`basename $0`
DOT=`pwd`

TRAILER="Install.$LOGNAME"
INSTALL_STATE=${INSTALL_STATE-$HOME/.Install.state}
export INSTALL_STATE
INSTALL_DIR=${INSTALL_DIR-/tmp/$TRAILER}
if [ "`basename $INSTALL_DIR`" != "$TRAILER" ]; then
	INSTALL_DIR="$INSTALL_DIR/$TRAILER"
fi
export INSTALL_DIR
INSTALL_LIB=${INSTALL_LIB-$HOME/LibInstall}
export INSTALL_LIB
INSTALL_RC=${INSTALL_RC-$HOME/.Installrc}
export INSTALL_RC
INSTALL_CP=${INSTALL_CP-"cp -p"}
export INSTALL_CP
INSTALL_RCP=${INSTALL_RCP-"rcp -p"}
export INSTALL_RCP

STATE=0

DEFAULT_OPTIONS="-naq"
GLOM=no
GLOMNAME=kernel
IMPL="default"
WANT32="yes"
WANT64="yes"

modlist=/tmp/modlist$$
# dummy directory for make state files.
modstatedir=/tmp/modstate$$

trap 'fail "User Interrupt" "You can resume by typing \"$INSTALL -R\""' 1 2 3 15

function usage {
	echo ""
	echo $1
	echo '
Usage: Install	[ -w workspace ]
		[ -s srcdir (default: usr/src/uts) ]
		[ -k karch (e.g. sun4u; required if not deducible from pwd) ]
		[ -t target (extract tar file on target, e.g. user@machine:/) ]
		[ -T target (copy tar file to target, e.g. user@machine:/tmp) ]
		[ -n (no target, just create tar file in /tmp (default)) ]
		[ -u (install unix only) ]
		[ -m (install modules only) ]
		[ -a (install everything, i.e. unix + modules (default)) ]
		[ -v (verbose output) ]
		[ -V (REALLY verbose output) ]
		[ -q (quiet (default)) ]
		[ -c (clean up (remove temp files) when done (default) ]
		[ -p (preserve temp files -- useful for debugging) ]
		[ -L (library create: put tarfile in $INSTALL_LIB/env.karch) ]
		[ -l lib (library extract: use $INSTALL_LIB/lib as source) ]
		[ -D libdir (default: $HOME/LibInstall) ]
		[ -d tempdir (Install work area (default: /tmp)) ]
		[ -G glomname (put all files under platform/karch/glomname) ]
		[ -i impl (e.g. sunfire; recommended with -G) ]
		[ -x (update /etc/name_to_major et al) ]
		[ -X (do not update /etc/name_to_major et al (default)) ]
		[ -P (update /etc/path_to_inst -- generally not advisable) ]
		[ -h (help -- prints this message) ]
		[ -R (recover a previous Install) ]
		[ -o objdir (object directory - either obj or debug (the default)) ]
		[ -K (do not copy kmdb) ]
		[ -3 32-bit modules only ]
		[ -6 64-bit modules only ]
		[ list of modules to install ]

For full details:

	man -M /ws/on297-gate/public/docs Install
'
	exit 1
}

#
# Save the current state of Install
#

function save_state {
	rm -f $INSTALL_STATE
	(echo "# State of previous Install
TARGET=$TARGET
ENV_PATH=$ENV_PATH
ENV_NAME=$ENV_NAME
KARCH=$KARCH
UTS=$UTS
INSTALL_DIR=$INSTALL_DIR
INSTALL_LIB=$INSTALL_LIB
IMODE=$IMODE
LIBCREATE=$LIBCREATE
LIBSRC=$LIBSRC
VERBOSE=$VERBOSE
CLEANUP=$CLEANUP
GLOM=$GLOM
GLOMNAME=$GLOMNAME
KMDB=$KMDB
files='$files'
STATE=$STATE" >$INSTALL_STATE) || verbose "Warning: cannot save state"
}

#
# Restore the previous state of Install
#

function restore_state {
	test -s $INSTALL_STATE || fail "Can't find $INSTALL_STATE"
	eval "`cat $INSTALL_STATE`"
}

#
# Install failed -- print error messages and exit 2
#

function fail {
	save_state
	#
	# We might have gotten here via a trap.  So wait for any
	# children (especially "make modlist") to exit before giving
	# the error message or cleaning up.
	#
	wait
	while [ $# -gt 0 ]
	do
		echo $1
		shift
	done
	rm -rf $modstatedir
	rm -f $modlist
	echo "Install failed"
	exit 2
}

#
# Echo a string in verbose mode only
#

function verbose {
	test "$VERBOSE" != "q" && echo $1
}

#
# hack for tmpfs bug -- remove files gradually
#

function remove_dir {
	test -d $1 || return
	local_dot=`pwd`
	cd $1
	touch foo
	rm -f `find . -type f -print`
	cd $local_dot
	rm -rf $1
}

#
# Create a directory if it doesn't already exist.
# mkdir will provide an error message, so don't provide an additional
# message.
#

function tstmkdir {
	[ -d $1 ] || mkdir -p $1 || fail
}

#
# Patch up target directories for glommed kernel.
# usage: fixglom listfile glomname
#

function fixglom {
	nawk \
	    -v glomname=$2 \
	    -v karch=$KARCH ' 
	$1 == "MOD" || $1 == "SYMLINK" {
		sub(/^platform.*kernel/, "platform/" karch "/" glomname, $4)
		sub(/^kernel/, "platform/" karch "/" glomname, $4)
		sub(/^usr.kernel/, "platform/" karch "/" glomname, $4)
		print
	}
	$1 == "LINK" {
		sub(/^platform.*kernel/, "platform/" karch "/" glomname, $3)
		sub(/^kernel/, "platform/" karch "/" glomname, $3)
		sub(/^usr.kernel/, "platform/" karch "/" glomname, $3)
		sub(/^platform.*kernel/, "platform/" karch "/" glomname, $5)
		sub(/^kernel/, "platform/" karch "/" glomname, $5)
		sub(/^usr.kernel/, "platform/" karch "/" glomname, $5)
		print
	}
	$1 == "CONF" {
		sub(/^platform.*kernel/, "platform/" karch "/" glomname, $3)
		sub(/^kernel/, "platform/" karch "/" glomname, $3)
		sub(/^usr.kernel/, "platform/" karch "/" glomname, $3)
		print
	}
	' $1 > $1.new
	mv $1.new $1
}

#
# Filter out implementation-specific modules, unless that
# implementation was requested by the user.
# usage: filtimpl listfile implname
#

function filtimpl {
	nawk \
	    -v impl=$2 '
	$1 == "MOD" || $1 == "SYMLINK" {
		if ($6 == "all" || $6 == impl)
			print
	}
	$1 == "CONF" {
		if ($5 == "all" || $5 == impl)
			print
	}
	$1 == "LINK" {
		if ($7 == "all" || $7 == impl)
			print
	}
	' $1 > $1.new
	mv $1.new $1
}

#
# Filter the module list to match the user's request.
# Usage: filtmod listfile modules
#
function filtmod {
	nawk -v reqstring="$2" '
	function modmatch(modname) {
		if (reqstring == "All") {
			return (1)
		} else if (reqstring == "Modules") {
			if (modname != "unix" && modname != "genunix")
				return (1)
		} else {
			if (modname in reqmods)
				return (1)
		}
		return (0)
	}
	BEGIN {
		#
		# The split call creates indexes 1, 2, 3, ...  We want
		# the module names as indexes.
		#
		split(reqstring, tmpmods)
		for (i in tmpmods)
			reqmods[tmpmods[i]] = 1
	}
	$1 == "MOD" {
		if (modmatch($3))
			print
	}
	$1 == "CONF" {
		if (modmatch($6))
			print
	}
	$1 == "SYMLINK" {
		if (modmatch($7))
			print
	}
	$1 == "LINK" {
		if (modmatch($4))
			print
	}
	' $1 > $1.new
	mv $1.new $1
}

#
# Unpack the crypto tarball into the given tree, then massage the
# tree so that the binaries are all in objNN or debugNN directories.
#
function unpack_crypto {
	typeset tarfile=$1
	typeset ctop=$2
	[ -d "$ctop" ] || fail "Can't create tree for crypto modules."

	[ "$VERBOSE" = "V" ] && echo "unpacking crypto tarball into $ctop..."
	bzcat "$tarfile" | (cd "$ctop"; tar xf -)

	typeset root="$ctop/proto/root_$MACH"
	[ $OBJD = obj ] && root="$ctop/proto/root_$MACH-nd"
	[ -d "$root" ] || fail "Can't unpack crypto tarball."

	(cd "$root"; for d in platform kernel usr/kernel; do
		[ ! -d $d ] && continue
		find $d -type f -print
	done) | while read file; do
		typeset dir=$(dirname "$file")
		typeset base=$(basename "$file")
		typeset type=$(basename "$dir")
		if [ "$type" = amd64 ]; then
			newdir="$dir/${OBJD}64"
		elif [ "$type" = sparcv9 ]; then
			newdir="$dir/${OBJD}64"
		else
			newdir="$dir/${OBJD}32"
		fi
		mkdir -p "$root/$newdir"
		[ "$VERBOSE" = "V" ] && echo "mv $file $newdir"
		mv "$root/$file" "$root/$newdir"
	done
}

#
# usage: fixcrypto listfile ctop
# Massage entries in listfile for crypto modules, so that they point
# into ctop.
#
function fixcrypto {
	typeset listfile=$1
	typeset ctop=$2

	typeset ccontents=/tmp/crypto-toc$$
	find "$ctop" -type f -print > $ccontents
	typeset root=root_$MACH
	[ "$OBJD" = obj ] && root=root_$MACH-nd

	grep -v ^MOD $listfile > $listfile.no-mod
	grep ^MOD $listfile | while read tag srcdir module targdir size impl; do
		#
		# We don't just grep for ${OBJD}$size/$module because
		# there can be generic and platform-dependent versions
		# of a module.
		#
		newsrcfile=$(grep -w $root/$targdir/${OBJD}$size/$module $ccontents)
		if [ -n "$newsrcfile" ]; then
			# srcdir doesn't include final objNN or debugNN
			echo $tag $module $targdir $size $impl \
			    $(dirname $(dirname "$newsrcfile"))
		else
			echo $tag $module $targdir $size $impl $srcdir
		fi
	done > $listfile.mod
	cat $listfile.mod $listfile.no-mod > $listfile

	rm -f $listfile.mod
	rm -f $listfile.no-mod
	rm -f $ccontents
}

#
# Copy a module, or create a link, as needed.
#

function copymod {
	case $1 in
	MOD)
		targdir=$INSTALL_FILES/$4
		tstmkdir $targdir
		target=$targdir/$3
		verbose "$INSTALL_CP $2/${OBJD}$5/$3 $target"
		$INSTALL_CP $2/${OBJD}$5/$3 $target || \
		    fail "can't create $target"
		;;
	SYMLINK)
		targdir=$INSTALL_FILES/$4
		tstmkdir $targdir
		target=$targdir/$5
		rm -f $target
		verbose "ln -s $3 $target"
		ln -s $3 $target || fail "can't create $target"
		;;
	LINK)
		targdir=$INSTALL_FILES/$5
		tstmkdir $targdir
		target=$targdir/$6
		rm -f $target
		verbose "ln $INSTALL_FILES/$3/$4 $target"
		ln $INSTALL_FILES/$3/$4 $target || fail "can't create $target"
		;;
	CONF)
		target=$INSTALL_FILES/$3
		tstmkdir `dirname $target`
		conffile=`basename $3`
		verbose "$INSTALL_CP $4/$conffile $target"
		$INSTALL_CP $4/$conffile $target
		;;
	*)
		fail "unrecognized modlist entry: $*"
		;;
	esac
}

# Sanity-check the given module list.
function check_modlist {
	nawk '
	BEGIN {
		nfields["MOD"] = 6
		nfields["CONF"] = 6
		nfields["LINK"] = 7
		nfields["SYMLINK"] = 7
	}
	{
		# This also catches unknown tags.
		if (nfields[$1] != NF) {
			print "error: invalid modlist record:"
			print $0
			print "expected", nfields[$1], "fields, found", NF
			status=1
		}
	}
	END {
		exit status
	}
	' $1 || fail "Errors in kernel module list"
}

#
# Copy kernel modules to $INSTALL_DIR
#

function copy_kernel {

	case $KARCH in
		sun4*)		ISA=sparc;	MACH=sparc	;;
		i86*)		ISA=intel;	MACH=i386	;;
		*)		fail "${KARCH}: invalid kernel architecture";;
	esac
	export MACH

	if [ "$GLOM" = "no" ]; then
		verbose "Source = $UTS, ISA = $ISA, kernel = $KARCH"
	else
		verbose "Source = $UTS, ISA = $ISA, kernel = $KARCH, impl = $IMPL"
	fi

	test -d $KARCH || fail "${KARCH}: invalid kernel architecture"
	test -d $ISA || fail "${ISA}: invalid instruction set architecture"

	tstmkdir $INSTALL_FILES
	rm -rf $modstatedir
	tstmkdir $modstatedir
	export MODSTATE=$modstatedir/state

	#
	# Figure out which "make" to use.  dmake is faster than serial
	# make, but dmake 7.3 has a bug that causes it to lose log
	# output, which means the modlist might be incomplete.
	#
	make=dmake
	dmvers=`$make -version`
	if [ $? -ne 0 ]; then
		make=/usr/ccs/bin/make
	elif [[ $dmvers = *Distributed?Make?7.3* ]]; then
		unset make
		searchpath="/ws/onnv-tools/SUNWspro/SOS10/bin
			/opt/SUNWspro/SOS10/bin
			/opt/SUNWspro/bin"
		for dmpath in $searchpath; do
			verbose "Trying $dmpath/dmake"
			if [ -x $dmpath/dmake ]; then
				dmvers=`$dmpath/dmake -version`
				if [[ $dmvers != *Distributed?Make?7.3* ]]; then
					make="$dmpath/dmake"
					break;
				fi
			fi
		done
		if [ -z $make ]; then
			make=/usr/ccs/bin/make
			echo "Warning: dmake 7.3 doesn't work with Install;" \
				"using $make"
		fi
	fi

	#
	# Get a list of all modules, configuration files, and links
	# that we might want to install.
	#
	verbose "Building module list..."
	(cd $KARCH; MAKEFLAGS=e $make -K $MODSTATE modlist.karch) | \
	    egrep "^MOD|^CONF|^LINK|^SYMLINK" > $modlist
	[ "$VERBOSE" = "V" ] && cat $modlist
	check_modlist $modlist
	if [ -n "$ON_CRYPTO_BINS" ]; then
		cryptotar="$ON_CRYPTO_BINS"
		if [ "$OBJD" = obj ]; then
			isa=$(uname -p)
			cryptotar=$(echo "$ON_CRYPTO_BINS" |
			    sed -e s/.$isa.tar.bz2/-nd.$isa.tar.bz2/)
		fi
		[ -f "$cryptotar" ] || fail "crypto ($cryptotar) doesn't exist"
		cryptotree=$(mktemp -d /tmp/crypto.XXXXXX)
		[ -n "$cryptotree" ] || fail "can't create tree for crypto"
		unpack_crypto "$cryptotar" "$cryptotree"
		#
		# fixcrypto must come before fixglom, because
		# fixcrypto uses the unglommed path to find things in
		# the unpacked crypto.
		#
		fixcrypto $modlist "$cryptotree"
	fi
	if [ "$GLOM" = "yes" ]; then
		fixglom $modlist $GLOMNAME
		filtimpl $modlist $IMPL
	fi
	if [[ -n "$files" && "$files" != All ]]; then
		filtmod $modlist "$files"
	fi

	#
	# Copy modules and create links.  For architectures with both
	# 32- and 64-bit modules, we'll likely have duplicate
	# configuration files, so do those after filtering out the
	# duplicates.
	#
	verbose "Copying files to ${INSTALL_FILES}..."

	#
	# The IFS is reset to the newline character so we can buffer the
	# output of grep without piping it directly to copymod, otherwise
	# if fail() is called, then it will deadlock in fail()'s wait call
	#
	OIFS="$IFS"
	IFS="
	"
	set -- `grep -v "^CONF" $modlist`;
	IFS="$OIFS"
	for onemod in "$@"; do
		copymod $onemod
	done
	
	OIFS="$IFS"
	IFS="
	"
	set -- `grep "^CONF" $modlist | sort | uniq`;
	IFS="$OIFS"
	for onemod in "$@"; do
		copymod $onemod
	done

	#
	# Add the glommed kernel name to the root archive
	#
	if [[ $GLOM == "yes" ]];
	then
		filelist="$INSTALL_FILES/etc/boot/solaris/filelist.ramdisk"
		mkdir -p `dirname $filelist`
		echo "platform/$KARCH/$GLOMNAME" >$filelist
	fi

	STATE=1 # all kernel modules copied correctly
	save_state
}

function kmdb_copy {
	typeset src="$1"
	typeset destdir="$2"

	if [[ ! -d $dest ]] ; then
		[[ "$VERBOSE" != "q" ]] && echo "mkdir -p $destdir"

		mkdir -p $destdir || fail "failed to create $destdir"
	fi

	[[ "$VERBOSE" != "q" ]] && echo "cp $src $destdir"

	cp $src $destdir || fail "failed to copy $src to $destdir"
}

function kmdb_copy_machkmods {
	typeset modbase="$1"
	typeset destdir="$2"
	typeset dir=
	typeset kmod=

	[[ ! -d $modbase ]] && return

	for dir in $(find $modbase -name kmod) ; do
		set -- $(echo $dir |tr '/' ' ')

		[[ $# -lt 2 ]] && fail "invalid mach kmod dir $dir"

		shift $(($# - 2))
		kmod=$1

		[[ ! -f $dir/$kmod ]] && continue

		kmdb_copy $dir/$kmod $destdir
	done
}

function kmdb_copy_karchkmods {
	typeset modbase="$1"
	typeset destdir="$2"
	typeset bitdir="$3"
	typeset dir=
	typeset kmod=
	typeset karch=

	[[ ! -d $modbase ]] && return

	for dir in $(find $modbase -name kmod) ; do
		set -- $(echo $dir | tr '/' ' ')

		[[ $# -lt 3 ]] && fail "invalid karch kmod dir $dir"

		shift $(($# - 3))
		kmod=$1
		bdir=$2

		[[ $bdir != $bitdir ]] && continue
		[[ ! -f $dir/$1 ]] && continue

		kmdb_copy $dir/$kmod $destdir
	done
}

function kmdb_copy_kmdbmod {
	typeset kmdbpath="$1"
	typeset destdir="$2"

	[[ ! -f $kmdbpath ]] && return 1

	kmdb_copy $kmdbpath $destdir

	return 0
}

function copy_kmdb {
	typeset kmdbtgtdir=$INSTALL_FILES/platform/$KARCH/$GLOMNAME/misc
	typeset bitdirs=
	typeset isadir=
	typeset b64srcdir=
	typeset b64tgtdir=
	typeset b32srcdir=
	typeset b32tgtdir=
	typeset machdir=
	typeset platdir=

	if [[ $KMDB = "no" || ! -d $SRC/cmd/mdb ]] ; then
		# The kmdb copy was suppressed or the workspace doesn't contain
		# the mdb subtree.  Either way, there's nothing to do.
		STATE=2
		save_state
		return
	fi

	if [[ $(mach) = "i386" ]] ; then
		isadir="intel"
		b64srcdir="amd64"
		b64tgtdir="amd64"
		b32srcdir="ia32"
		b32tgtdir="."
	else
		isadir="sparc"
		b64srcdir="v9"
		b64tgtdir="sparcv9"
		b32srcdir="v7"
		b32tgtdir="."
	fi

	typeset foundkmdb=no
	typeset kmdbpath=
	typeset destdir=

	platdir=$INSTALL_FILES/platform/$KARCH/$GLOMNAME
	if [[ $GLOM = "yes" ]] ; then
		machdir=$platdir
	else
		machdir=$INSTALL_FILES/kernel
	fi

	srctrees=$SRC
	if [ -z "$ON_CRYPTO_BINS" ]; then
		echo "Warning: ON_CRYPTO_BINS not set; pre-signed" \
		    "crypto not provided."
	fi
	if [[ $WANT64 = "yes" ]] ; then
		# kmdbmod for sparc and x86 are built and installed
		# in different places
		if [[ $(mach) = "i386" ]] ; then
			kmdbpath=$SRC/cmd/mdb/$isadir/$b64srcdir/kmdb/kmdbmod
			destdir=$machdir/misc/$b64tgtdir
		else
			kmdbpath=$SRC/cmd/mdb/$KARCH/$b64srcdir/kmdb/kmdbmod
			destdir=$platdir/misc/$b64tgtdir
		fi

		if kmdb_copy_kmdbmod $kmdbpath $destdir ; then
			foundkmdb="yes"

			for tree in $srctrees; do
				kmdb_copy_machkmods \
				    $tree/cmd/mdb/$isadir/$b64srcdir \
				    $machdir/kmdb/$b64tgtdir
				kmdb_copy_karchkmods $tree/cmd/mdb/$KARCH \
				    $platdir/kmdb/$b64tgtdir $b64srcdir
			done
		fi
	fi

	if [[ $WANT32 = "yes" ]] ; then
		kmdbpath=$SRC/cmd/mdb/$isadir/$b32srcdir/kmdb/kmdbmod
		destdir=$machdir/misc/$b32tgtdir

		if kmdb_copy_kmdbmod $kmdbpath $destdir ; then
			foundkmdb="yes"

			for tree in $srctrees; do
				kmdb_copy_machkmods \
				    $tree/cmd/mdb/$isadir/$b32srcdir \
				    $machdir/kmdb/$b32tgtdir
				kmdb_copy_karchkmods $tree/cmd/mdb/$KARCH \
				    $platdir/kmdb/$b32tgtdir $b32srcdir
			done
		fi
	fi

	# A kmdb-less workspace isn't fatal, but it is potentially problematic,
	# as the changes made to uts may have altered something upon which kmdb
	# depends.  We will therefore remind the user that they haven't built it
	# yet.
	if [[ $foundkmdb != "yes" ]] ; then
		echo "WARNING: kmdb isn't built, and won't be included"
	fi

	STATE=2
	save_state
	return
}

#
# Make tarfile
#

function make_tarfile {
	echo "Creating tarfile $TARFILE"
	test -d $INSTALL_FILES || fail "Can't find $INSTALL_FILES"
	cd $INSTALL_FILES
	rm -f $TARFILE files

	# We don't want to change the permissions or ownership of pre-existing
	# directories on the target machine, so we're going to take care to
	# avoid including directories in the tarfile.  On extraction, tar won't
	# modify pre-existing directories, and will create non-existent ones as
	# the user doing the extraction.
	find . ! -type d -print |fgrep -vx './files' >files
	tar cf $TARFILE -I files || fail "Couldn't create tarfile $TARFILE"
	STATE=3
}

#
# Routines to copy files to the target machine
#

function remote_fail {
	fail "" "$1" "" \
		"Make sure that $TARGET_MACHINE is up." \
"Check .rhosts in the home directory of user $TARGET_USER on $TARGET_MACHINE." \
		"Check /etc/hosts.equiv, /etc/passwd, and /etc/shadow." \
		"Change permissions on $TARGET_MACHINE as necessary." \
		"Then, use \"$INSTALL -R\" to resume the install." ""
}

function remote_install {
	if [ "$IMODE" = "n" ]; then
		STATE=4
		return 0
	fi
	test -s $TARFILE || fail "$TARFILE missing or empty"
	verbose "Installing system on $TARGET"
	test -d $INSTALL_DIR || fail "Can't find $INSTALL_DIR"
	cd $INSTALL_DIR
	rm -f errors fatal nonfatal
	if [ "$IMODE" = "T" ]; then
		EMESG="Can't rcp to $TARGET"
		touch errors
		sh -e${SHV}c "$INSTALL_RCP $TARFILE $TARGET/Install.tar"
	else
		EMESG="Can't rsh to $TARGET_MACHINE"
		rsh -l $TARGET_USER $TARGET_MACHINE \
		    "(cd $TARGET_DIR; /usr/bin/tar x${V}f -)" \
		    <$TARFILE 2>errors
	fi
	test $? -ne 0 && remote_fail "$EMESG"
	cd $INSTALL_DIR
	egrep "set time|warning|blocksize" errors >nonfatal
	egrep -v "set time|warning|blocksize" errors >fatal
	if [ -s fatal ]; then
		echo "Fatal errors from rsh:"
		cat fatal
		remote_fail "Can't install on $TARGET_MACHINE"
	fi
	if [ -s nonfatal -a "$VERBOSE" != "q" ]; then
		echo "Non-fatal errors from rsh:"
		cat nonfatal
	fi
	rm -f fatal nonfatal errors
	test "$IMODE" = "T" && echo "Files can be extracted on \
$TARGET_MACHINE using 'tar xvf $TARGET_DIR/Install.tar'"
	STATE=4
}

function okexit {
	cd /tmp
	test "$CLEANUP" = c && remove_dir $INSTALL_DIR
	save_state
	rm -rf $modstatedir
	rm -f $modlist
	[ -n "$cryptotree" ] && rm -rf "$cryptotree"
	verbose "Install complete"
	exit 0
}

#
# Process options
#

RCOPTS=""
LIBCREATE="no"
LIBSRC=""
ENV_PATH=$CODEMGR_WS
OBJD="debug"
KMDB="yes"

test -s $INSTALL_RC && RCOPTS=`cat $INSTALL_RC`
set $INSTALL $DEFAULT_OPTIONS $RCOPTS $*
shift

while getopts acd:D:G:hi:k:Kl:Lmno:pPqRs:t:T:uvVw:xX36 opt
do
	case $opt in
	    w)	ENV_PATH="$OPTARG"; SRC="$ENV_PATH/usr/src";;
	    s)	UTS="$OPTARG";;
	    k)	KARCH="$OPTARG";;
	  t|T)	TARGET="$OPTARG"; IMODE=$opt; CLEANUP="c";;
	    n)	TARGET=""; IMODE="n"; CLEANUP="p";;
	    u)	files="unix genunix";;
	    m)	files="Modules";;
	    a)	files="All";;
	v|V|q)	VERBOSE=$opt;;
	  c|p)	CLEANUP=$opt;;
	    L)	LIBCREATE="yes"; CLEANUP="c";;
	    l)	LIBSRC="$OPTARG";;
	    D)	INSTALL_LIB="$OPTARG";;
	    d)	INSTALL_DIR="$OPTARG/$TRAILER";;
	    G)	GLOM=yes; GLOMNAME="$OPTARG";;
	P|X|x)	echo "-$opt is obsolete; ignored";;
	    h)	usage "${INSTALL}: installs unix and modules";;
	    R)	x=$OPTIND; restore_state; OPTIND=$x;;
	    i)	IMPL="$OPTARG";;
	    o)	OBJD="$OPTARG";;
	    K)  KMDB="no";;
	    3)  WANT64="no";;
	    6)  WANT32="no";;
	   \?)	usage "Illegal option";;
	esac
done
shift `expr $OPTIND - 1`

ENV_NAME=`basename $ENV_PATH`

#
# The rest of the command line is a list of individual files to copy.
# If non-null, this list overrides the -uma options.
#

if [[ $# -gt 0 ]] ; then
	files="$*"
	KMDB="no"
fi

case "$VERBOSE" in
	v)	V="v"; SHV="x";;
	V)	V="v"; SHV="x"; set -x;;
	q)	V=""; SHV="";;
esac

#
# Create temp directory for Install's files
#

tstmkdir $INSTALL_DIR

TARFILE=$INSTALL_DIR/Install.${KARCH}.tar
INSTALL_FILES=$INSTALL_DIR/$KARCH

#
# Extract the target machine and target directory from a target of the
# form [user@]machine:/dir .
#

if [ "$IMODE" != "n" ]; then
	eval `echo $TARGET | nawk -F':' '{ 
		if (NF != 2 || !length($1) || !length($2))
			print "usage \"Invalid target\""
		m = $1; d = $2
		if ($1 ~ /@/) {
		    k = split($1, f, "@");
		    if (k != 2 || !length(f[1]) || !length (f[2]))
			    print "usage \"Invalid target\""
		    u = f[1]; m = f[2]
		}
		print "TARGET_USER=" u ";"
		print "TARGET_MACHINE=" m ";"
		print "TARGET_DIR=" d ";"
	}'`
	if [ -z "$TARGET_USER" ]; then
		TARGET_USER=$LOGNAME
	fi
fi

#
# Allow the use of library source or target for the install
#

if [ -n "$LIBSRC" ]; then
	LIBSRC="`basename $LIBSRC .tar`.tar"
	TARFILE=$INSTALL_LIB/$LIBSRC
	test -s $TARFILE || fail "Can't find tarfile $TARFILE"
	verbose "Installing from library tarfile $TARFILE"
	STATE=3
elif [ "$LIBCREATE" = "yes" ]; then
	tstmkdir $INSTALL_LIB
	TARFILE="$INSTALL_LIB/${ENV_NAME}.${KARCH}.tar"
fi

#
# The next few lines allow recovery and activation with -R,
# and library installs with -l.
#

[[ $STATE -eq 1 ]] && copy_kmdb
[[ $STATE -eq 2 ]] && make_tarfile
[[ $STATE -eq 3 ]] && remote_install
[[ $STATE -eq 4 ]] && okexit

save_state

cd $DOT
DOTDOT=`cd ..; pwd`

#
# Try to be smart: if DOTDOT ends in uts, then infer UTS and KARCH from DOT
# Otherwise, if SRC is set, infer UTS = $SRC/uts.
#

if [ "`basename $DOTDOT`" = "uts" ]; then
	UTS=$DOTDOT
	KARCH=`basename $DOT`
	if [ ! -n "$SRC" ]; then
		SRC=`dirname $DOTDOT`
		verbose "Setting SRC to $SRC"
	fi
	export SRC
fi

if [ -z "$UTS" -a -n "$SRC" ]; then
	UTS="${SRC}/uts"
	test -n "$KARCH" || fail "no karch specified (e.g. -k sun4u)"
fi

if [ "$LIBCREATE" = "yes" ]; then
	TARFILE=$INSTALL_LIB/${ENV_NAME}.${KARCH}.tar
else
	TARFILE=$INSTALL_DIR/Install.${KARCH}.tar
fi
INSTALL_FILES=$INSTALL_DIR/$KARCH
save_state

cd $DOT
test -z "$UTS" && fail 'Cannot find kernel sources -- $SRC not set'
test -d "$UTS" || fail "${UTS}: no such directory"

#
# Convert UTS into an absolute path.
#

cd $UTS
UTS=`pwd`

test "`basename $UTS`" = "uts" || \
	verbose "Warning: source path $UTS doesn't end in 'uts'"

remove_dir $INSTALL_DIR/$KARCH
rm -f $TARFILE

copy_kernel	# sets STATE=1 if successful
copy_kmdb	# sets STATE=2 if successful
make_tarfile	# sets STATE=3 if successful
remote_install	# sets STATE=4 if successful

okexit
