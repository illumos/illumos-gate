#!/bin/ksh
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#From: "@(#)Install	1.56	96/10/11 SMI"
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Author:  Jeff Bonwick
#
#	Please report any bugs to bonwick@eng.
#
# How Install works:
#
#	Install performs the following steps:
#
#	1. Figure out how to construct /kernel by looking at Makefile.uts,
#	   Makefile.$ISA (sparc default), Makefile.$KARCH and the Makefiles
#	   in the module directories (uts/arch/*/Makefile).
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

DEFAULT_OPTIONS="-naqX"
GLOM=no
GLOMNAME=kernel
IMPL="default"
WANT32="yes"
WANT64="yes"

trap 'fail "User Interrupt" "You can resume by typing \"$INSTALL -R\""' 1 2 3 15

usage() {
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

save_state() {
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
XFLAG=$XFLAG
files='$files'
STATE=$STATE" >$INSTALL_STATE) || verbose "Warning: cannot save state"
}

#
# Restore the previous state of Install
#

restore_state() {
	test -s $INSTALL_STATE || fail "Can't find $INSTALL_STATE"
	eval "`cat $INSTALL_STATE`"
}

#
# Install failed -- print error messages and exit 2
#

fail() {
	save_state
	while [ $# -gt 0 ]
	do
		echo $1
		shift
	done
	echo "Install failed"
	exit 2
}

#
# Echo a string in verbose mode only
#

verbose() {
	test "$VERBOSE" != "q" && echo $1
}

#
# hack for tmpfs bug -- remove files gradually
#

remove_dir() {
	test -d $1 || return
	local_dot=`pwd`
	cd $1
	touch foo
	rm -f `find . -type f -print`
	cd $local_dot
	rm -rf $1
}

#
# Copy kernel modules to $INSTALL_DIR
#

copy_kernel() {
	# The awk script below looks in Makefile.uts to find out what module
	# subdirectories to make.  It then looks in Makefile.$KARCH (for root
	# modules) and Makefile.$ISA (for usr modules) to create a list of
	# all possible modules.  Finally, it looks at each module's Makefile
	# to determine where it belongs and what links are required.
	# This script makes three assumptions:
	#
	# 1) Module subdirectories are specified in Makefile.uts by lines of the
	#    form:
	#
	#	ROOT_FOO_DIR = $(ROOT_MOD_DIR)/foo
	#	USR_BAR_DIR = $(USR_MOD_DIR)/bar
	#
	# 2) The corresponding lists of modules appear in Makefile.$KARCH and
	#    Makefile.$ISA on one or more lines of the form:
	#
	#	FOO_KMODS = foo bar
	#	FOO_KMODS += red white blue
	#
	# 3) Each module directory has a Makefile with lines of the form:
	#
	#	ROOTMODULE = $(ROOT_FOO_DIR)/$(MODULE)
	#	USRMODULE = $(USR_FOO_DIR)/$(MODULE)
	#	ROOTLINK* = $(ROOT_BAR_DIR)/something
	#	USRLINK* = $(USR_BAR_DIR)/something
	#
	# If the structure of Makefile.{$KARCH,uts,$ISA} changes in a way that
	# invalidates these assumptions, you'll need to pick up a new version of
	# Install.

	case $KARCH in
		sun4*)		ISA=sparc;	MACH=sparc;	SUBISA_MAKE=;;
		i86pc)		ISA=intel;	MACH=i386;	SUBISA_MAKE=$ISA/ia32/Makefile.ia32;;
		*)		fail "${KARCH}: invalid kernel architecture";;
	esac

	if [ "$GLOM" = "no" ]; then
		verbose "Source = $UTS, ISA = $ISA, kernel = $KARCH"
	else
		verbose "Source = $UTS, ISA = $ISA, kernel = $KARCH, impl = $IMPL"
	fi

	UTS_MAKE=Makefile.uts
	ISA_MAKE=$ISA/Makefile.$ISA
	KARCH_MAKE=$KARCH/Makefile.$KARCH
	PSM_MAKE=$UTS/../Makefile.psm

	test -d $KARCH || fail "${KARCH}: invalid kernel architecture"
	test -d $ISA || fail "${ISA}: invalid instruction set architecture"
	test -s $UTS_MAKE || fail "Can't find $UTS_MAKE"
	test -s $ISA_MAKE || fail "Can't find $ISA_MAKE"
	test -s $KARCH_MAKE || fail "Can't find $KARCH_MAKE"
	test -s $PSM_MAKE || fail "Can't find $PSM_MAKE"

	#
	# For 5.8 and 5.9 we used to build a few x86 things in an ia32 subdirectory
	#
	[[ -n "$SUBISA_MAKE" && -s "$SUBISA_MAKE" ]] || SUBISA_MAKE=;

	if [ $GLOM = "yes" ]; then
		if [ -f $KARCH/$IMPL/Makefile.$IMPL ]; then
			IMPL_MAKE="$KARCH/$IMPL/Makefile.$IMPL"
		fi
	else
		IMPL_MAKE=`nawk -v karch="$KARCH" '
			$1 == "IMPLEMENTATIONS" {
			for (i = 3; i <= NF; i++)
				if ($i != ".WAIT")
					printf("%s ", karch "/" $i "/Makefile." $i)
			}' $KARCH_MAKE`
	fi

	DEVFS="./$ISA/devfs/Makefile"

	verbose "Copying files to ${INSTALL_FILES}..."
	test -d $INSTALL_FILES || mkdir -p $INSTALL_FILES

	nawk \
		-v isa="$ISA" \
		-v mach="$MACH" \
		-v insd="$INSTALL_FILES" \
		-v files="$files" \
		-v verbose=$VERBOSE \
		-v karch=$KARCH \
		-v copy="$INSTALL_CP" \
		-v devfs=$DEVFS \
		-v auxfiles=$XFLAG \
		-v ptiflag=$PFLAG \
		-v glom=$GLOM \
		-v glomname=$GLOMNAME \
		-v impl=$IMPL \
		-v objd=$OBJD \
		-v want32=$WANT32 \
		-v want64=$WANT64 \
		'
	function run(s) {
		if (verbose != "q")
			print s
		if (system(s))
			exit 1
	}
	function cpf(f1,f2) {
		if (verbose != "q")
			print copy " " f1 " " f2
		if (system(copy " " f1 " " f2))
			print "WARNING: copy of " f1 " failed"
	}
	function mkdir(dir) {
		if (!touched[dir]) {
			run("test -d " dir " || mkdir -p " dir)
			touched[dir]=1
		}
		return dir
	}
	function vprint(s) {
		if (verbose == "V")
			print s
	}
	function try_run(s) {
		if (verbose != "q")
			print s
		if (system(s))
			return 1
		return 0
	}
	function exist(s) {
		if (verbose != "q")
			print "test -f " s
		return !system("test -f " s)
	}

	function copymod(src, targ, om) {
		if (om) {
			run("if [ -f " src " ] ; then " \
			    copy " " src " " targ " ; fi")
		} else {
			run(copy " " src " " targ)
		}
	}

	function copymod32(idx, modtarg) {
		modsrc = modsrcd[idx] "/" objd32 "/" modname[idx]

		if (!exist(modsrc))
			return (0)

		copymod(modsrc, modtarg, optmod[idx])
		return (1)
	}	

	function copymod64(idx, modtarg) {
		modsrc = modsrcd[idx] "/" objd64 "/" modname[idx]

		if (!exist(modsrc))
			return (0)

		copymod(modsrc, modtarg subdir64, optmod[idx])
		return (1)
	}

	function linkmod(lmod, idx, modtarg, did32, did64) {
		if (lmod ~ /^...MODULE.$/)
			lmod = "/" modname[idx]

		if (did32 == "yes") {
			m = modtarg "/" modname[i]
			run("rm -f " dir lmod "; ln " m " " dir lmod)
		}

		if (did64 == "yes") {
			m = modtarg subdir64 "/" modname[i]
			run("rm -f " dir subdir64 lmod "; ln " m " " \
			    dir subdir64 lmod)
		}
	}

	function slinkmod(slinktarg, idx, modtarg, did32, did64) {
		if (did32 == "yes") {
			slink = modtarg "/" slinktarg
			run("rm -f " slink "; ln -s " modname[i] " " slink)
		}

		if (did64 == "yes") {
			slink = modtarg subdir64 "/" slinktarg
			run("rm -f " slink "; ln -s " modname[i] " " slink)
		}
	}

	BEGIN {
		# If you do NOT want the SVVS modules, set svvs to 0.
		svvs=1
		# If you do NOT want the excluded modules, set xmods to 0.
		xmods=1

		machkernel = "/platform/" karch "/" glomname

		nmods=0
		do32="no"
		do64="no"
		objd32=objd "32"
		objd64=objd "64"
		build64and32="no"
	}

	$1 == "SUBDIR64_" mach {
		vprint($0)
		subdir64="/" $3
		subdir64_relative=$3
	}

	FILENAME == "Makefile.uts" && $1 == "ALL_BUILDS64" {
		vprint($0)
		if ($0 ~ /32/)
			build64and32="yes"
	}

	FILENAME == karch "/Makefile." karch && $1 == "ALL_BUILDS" {
		vprint($0)
		if ($3 ~ /32/)
			do32=want32
		if ($4 ~ /32/)
			build64and32="yes"
		if ($3 ~ /ALL_BUILDS64/ && build64and32 == "yes")
			do32=want32
		if ($3 ~ /64/ && want64)
			do64=want64
	}

	$1 ~ /^(ROOT|USR)_.+_DIR(_32)?$/ {
		vprint($0)
		if ($3 ~ /_..CLASS..$/)
			next
		slash=index($3,"/")
		sub(/_32$/,"",$1)
		if (!slash)
			slash=length($3)+1
		parent=substr($3,3,slash-4)
		subdir=substr($3,slash)
		if (parent == "ROOT")
			child=subdir
		else if (moddirs[parent]) {
			if ($3 ~ /..PLATFORM.$/)
				child=moddirs[parent] "/" karch
			else
				child=moddirs[parent] subdir
		} else {
			print "missing mod dir " parent
			exit 1
		}
		moddirs[$1]=child
		sub(/^.*kernel/,machkernel,child)
		glomdirs[$1]=child
		n=split($1,foo,"_")
		if (n == 4 && foo[2] != "PSM")
			notdef[$1]=tolower(foo[2])
	}

	FILENAME != isa "/Makefile." isa && $1 ~ /^(GENLIB|UNIX)_DIR$/ {
		vprint($0)
		n=split($3,foo,"/")
		slash=index($3,"/")
		dir="." substr($3,slash)
		sub(/..PLATFORM./,karch,dir)
		nmods++
		modsrcd[nmods]=dir
		modname[nmods]=foo[n]
		unixmod[nmods]=1
	}

	FILENAME != "Makefile.uts" && $1 ~ /KMODS|XMODS/ &&
	    $1 != "GENUNIX_KMODS" {
		dir = FILENAME;
		sub(/\/Makefile.*$/, "", dir);
		if ($1 ~ "^SVVS_")
			if (svvs == 0)
				next
			else
				dir = dir "/svvs"
		if ($1 ~ "XMODS" && xmods == 0)
			next
		if ($0 !~ /\$/) {
			vprint($0)
			for (i = 3; i <= NF; i++) {
				if ($i ~ /^(ramdisk|wsdrv|vdi)$/)
					continue;
				nmods++
				modname[nmods]=$i
				modsrcd[nmods]="./" dir "/" $i
				if ($1 ~ "^MPSAS_")
					optmod[nmods] = 1
			}
		}
	}

	FILENAME == karch "/Makefile." karch && $1 == "PLATFORMS" &&
	    $3 !~ /\(/ {
		for (i = 3; i <= NF; i++)
			mkdir(insd "/platform/" $i)
	}

	FILENAME == karch "/Makefile." karch && ($1 == "IMPLEMENTED_PLATFORM" ||
	    $1 == "LINKED_PLATFORMS") {
		for (i = 3; i <= NF; i++)
			mkdir(insd "/platform/" $i)
	}

	FILENAME != "Makefile.uts" && $1 == "CONFS" {
		for (i = 3; i <= NF; i++) {
			kbi_brain_damage[$i] = "yes"
		}
	}

	END {
		split(files, modlist)
		for (m in modlist) {
			mm = modlist[m]
			if (mm == "modules") {
				for (i = 1; i <= nmods; i++)
					if (unixmod[i] == 0)
						modcopy[i]=1
				continue
			}
			nomodfound = 1
			for (i = 1; i <= nmods; i++) {
				if (modname[i] == mm) {
					modcopy[i]=1
					nomodfound = 0
				}
			}
			if (nomodfound) {
				print mm ": invalid module"
				exit 1
			}
		}

		for(i = 1; i <= nmods; i++) {
			if (!modcopy[i]) 
				continue

			confsrc = ""
			drvfiles[1] = ""
			classfile = ""
			ptifile = ""
			did32=do32
			did64=do64
			no_builds="false"
			modmake=modsrcd[i] "/Makefile"

			while (getline <modmake > 0) {
				if ($1 == "NO_BUILDS") {
					vprint($0)
					no_builds="true"
				}

				if ($1 == "ALL_BUILDS" && $3 ~ /64/) {
					vprint($0)
					did32="ok"
				}

				if ($1 == "ALL_BUILDS" && $3 ~ /32/) {
					vprint($0)
					did64="ok"
				}

				if ($1 ~ /^(MODULE|UNIX)$/) {
					vprint($0)
					modname[i] = $3
				}

				if ($1 ~ /^(ROOT|USR)(LINK|MODULE$)/) {
					vprint($0)
					slash=index($3,"/")
					parent=substr($3,3,slash-4)

					if (notdef[parent] &&
					    notdef[parent] != impl &&
					    glom == "yes") {
						confsrc = ""
						break
					}

					dir = (glom == "no") ? \
					    moddirs[parent] : glomdirs[parent]
					if (!dir) {
						print "no parent for " modname[i]
						exit 1
					}

					dir=insd dir
					mkdir(dir)

					if (do64 == "yes")
						mkdir(dir subdir64)

					if ($1 ~ /^(ROOT|USR)MODULE$/) {
						modtarg=dir
						conftarg=dir
						if (modname[i] in \
						    kbi_brain_damage) {
							confsrc = "./" karch \
							    "/io"
							conftarg = insd \
							    machkernel "/drv"

							mkdir(conftarg)

							if (do64 == "yes") {
								mkdir(conftarg \
								    subdir64)
							}
						}

						if (do32 == "yes" &&
						    !copymod32(i, modtarg))
							did32="no"

						if (do64 == "yes" &&
						    !copymod64(i, modtarg))
							did64="no"

					} else {
						linkmod(substr($3, slash),
						    i, modtarg, did32, did64)
					}
				}

				if ($1 == "SOFTLINKS") {
					vprint($0)
					for (j = 3; j <= NF; j++) {
						slinkmod($j, i, modtarg, did32,
						    did64)
					}
				}

				if ($1 == "CONF_SRCDIR") {
					vprint($0)
					slash = index($3, "/")
					confsrc = "." substr($3, slash)
				}
			}

			if (do32 == "yes" && did32 == "no" &&
			    no_builds == "false") {
				print "missing 32b file " confsrc "/" modname[i]
				exit 1
			}

			if (do64 == "yes" && did64 == "no" &&
			    no_builds == "false") {
				print "missing 64b file " confsrc "/" modname[i]
				exit 1
			}

			if (confsrc != "") {
				conffile = confsrc "/" modname[i] ".conf"
				cpf(conffile, conftarg)
			}

			close(modmake)
		}

		#
		# Make symlinks for KBI for different root node names for a
		# given platform
		#
		km = "./" karch "/Makefile"
		while (getline <km > 0) {
			if ($1 == "PLAT_LINKS") {
				for (i = 3; i <= NF; i++) {
					mkdir(insd "/platform")
					run("ln -s " karch " " insd \
					    "/platform/" $i)
				}
			}
		}
		close(km)

		if (did64 == "yes" && build64and32 == "no" &&
		    (try_run("test -f " insd "/platform/" karch "/" \
		    glomname "/" subdir64_relative "/unix") == 0))
		{
			run("ln -s " subdir64_relative "/unix " insd \
			    "/platform/" karch "/" glomname "/unix")

			if (isa == "sparc" && glom == "no" &&
			    (try_run("test -f " insd \
			     "/platform/SUNW,Ultra-Enterprise-10000/" glomname \
			     "/" subdir64_relative "/unix") == 0)) {
				run("ln -s " subdir64_relative "/unix " insd \
				    "/platform/SUNW,Ultra-Enterprise-10000/" \
				    glomname "/unix")
			}
		}

		while (getline <devfs > 0) {
			if ($1 == "SRCDIR")
				configdir = "." substr($3, index($3, "/")) "/"
			if ($1 == "CLASSFILE")
				classfile = $3
			if ($1 == "PTIFILE")
				ptifile = $3
			if ($1 == "DRVFILES")
				split(substr($0, index($0, $3)), drvfiles)
		}
		close(devfs)

		if (classfile != "" && auxfiles == 1) {
			dir = mkdir(targ["ROOT_DRV"])
			cpf(configdir classfile, dir)
		}

		if (ptifile != "" && ptiflag == 1) {
			dir = mkdir(insd "/etc")
			cpf(configdir ptifile, dir)
		}

		if (drvfiles[1] != "" && auxfiles == 1) {
			dir = mkdir(insd "/etc")
			for (file in drvfiles)
				cpf(configdir drvfiles[file], dir)
		}
	}' $UTS_MAKE $PSM_MAKE $ISA_MAKE $SUBISA_MAKE $KARCH_MAKE $IMPL_MAKE
	[[ $? -ne 0 ]] && fail "Files missing in environment"

	#
	# on x86, add the glommed kernel name to the root archive
	#
	if [[ $KARCH = "i86pc" && $GLOM == "yes" ]]; then
		filelist="$INSTALL_FILES/etc/boot/solaris/filelist.ramdisk"
		mkdir -p `dirname $filelist`
		echo "platform/$KARCH/$GLOMNAME" >$filelist
	fi

	STATE=1 # all kernel modules copied correctly
	save_state
}

kmdb_copy() {
	typeset src="$1"
	typeset destdir="$2"

	if [[ ! -d $dest ]] ; then
		[[ $VERBOSE != "q" ]] && echo "mkdir -p $destdir"

		mkdir -p $destdir || fail "failed to create $destdir"
	fi

	[[ $VERBOSE != "q" ]] && echo "cp $src $destdir"

	cp $src $destdir || fail "failed to copy $src to $destdir"
}

kmdb_copy_machkmods() {
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

kmdb_copy_karchkmods() {
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

kmdb_copy_kmdbmod() {
	typeset kmdbpath="$1"
	typeset destdir="$2"

	[[ ! -f $kmdbpath ]] && return 1

	kmdb_copy $kmdbpath $destdir

	return 0
}

copy_kmdb() {
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

	platdir=$INSTALL_FILES/platform/$KARCH/$GLOMNAME
	if [[ $GLOM = "yes" ]] ; then
		machdir=$platdir
	else
		machdir=$INSTALL_FILES/kernel
	fi

	kmdbpath=$SRC/cmd/mdb/$KARCH/$b64srcdir/kmdb/kmdbmod
	if [[ $WANT64 = "yes" ]] ; then
		if kmdb_copy_kmdbmod $kmdbpath $platdir/misc/$b64tgtdir ; then
			foundkmdb="yes"

			kmdb_copy_machkmods $SRC/cmd/mdb/$isadir/$b64srcdir \
			    $machdir/kmdb/$b64tgtdir
			kmdb_copy_karchkmods $SRC/cmd/mdb/$KARCH \
			    $platdir/kmdb/$b64tgtdir $b64srcdir
		fi
	fi

	kmdbpath=$SRC/cmd/mdb/$isadir/$b32srcdir/kmdb/kmdbmod
	if [[ $WANT32 = "yes" ]] ; then
		if kmdb_copy_kmdbmod $kmdbpath $machdir/misc/$b32tgtdir ; then
			foundkmdb="yes"

			kmdb_copy_machkmods $SRC/cmd/mdb/$isadir/$b32srcdir \
			    $machdir/kmdb/$b32tgtdir
			kmdb_copy_karchkmods $SRC/cmd/mdb/$KARCH \
			    $platdir/kmdb/$b32tgtdir $b32srcdir
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

make_tarfile() {
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

remote_fail() {
	fail "" "$1" "" \
		"Make sure that $TARGET_MACHINE is up." \
"Check .rhosts in the home directory of user $TARGET_USER on $TARGET_MACHINE." \
		"Check /etc/hosts.equiv, /etc/passwd, and /etc/shadow." \
		"Change permissions on $TARGET_MACHINE as necessary." \
		"Then, use \"$INSTALL -R\" to resume the install." ""
}

remote_install() {
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

okexit() {
	cd /tmp
	test "$CLEANUP" = c && remove_dir $INSTALL_DIR
	save_state
	verbose "Install complete"
	exit 0
}

#
# Process options
#

RCOPTS=""
LIBCREATE="no"
LIBSRC=""
PFLAG=0
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
	    m)	files="modules";;
	    a)	files="unix genunix modules";;
	v|V|q)	VERBOSE=$opt;;
	  c|p)	CLEANUP=$opt;;
	    L)	LIBCREATE="yes"; CLEANUP="c";;
	    l)	LIBSRC="$OPTARG";;
	    D)	INSTALL_LIB="$OPTARG";;
	    d)	INSTALL_DIR="$OPTARG/$TRAILER";;
	    G)	GLOM=yes; GLOMNAME="$OPTARG";;
	    x)	XFLAG=1;;
	    X)	XFLAG=0;;
	    P)	PFLAG=1;;
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

case $VERBOSE in
	v)	V="v"; SHV="x";;
	V)	V="v"; SHV="x"; set -x;;
	q)	V=""; SHV="";;
esac

#
# Create temp directory for Install's files
#

test -d $INSTALL_DIR || mkdir -p $INSTALL_DIR || fail "Can't mkdir $INSTALL_DIR"

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
	test -d $INSTALL_LIB \
		|| mkdir -p $INSTALL_LIB \
		|| fail "Can't mkdir $INSTALL_LIB"
	TARFILE="$INSTALL_LIB/${ENV_NAME}.${KARCH}.tar"
fi

#
# The next three lines allow recovery and activation with -R,
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
