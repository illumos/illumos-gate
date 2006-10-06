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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Based on the nightly script from the integration folks,
# Mostly modified and owned by mike_s.
# Changes also by kjc, dmk.
#
# BRINGOVER_WS may be specified in the env file.
# The default is the old behavior of CLONE_WS
#
# -i on the command line, means fast options, so when it's on the
# command line (only), lint and check builds are skipped no matter what 
# the setting of their individual flags are in NIGHTLY_OPTIONS.
#
# LINTDIRS can be set in the env file, format is a list of:
#
#	/dirname-to-run-lint-on flag
#
#	Where flag is:	y - enable lint noise diff output
#			n - disable lint noise diff output
#
#	For example: LINTDIRS="$SRC/uts n $SRC/stand y $SRC/psm y"
#
# -A flag in NIGHTLY_OPTIONS checks ABI diffs in .so files
# This option requires a couple of scripts.
#
# OPTHOME and TEAMWARE may be set in the environment to override /opt
# and /opt/teamware defaults.
#

#
# The CDPATH variable causes ksh's `cd' builtin to emit messages to stdout
# under certain circumstances, which can really screw things up; unset it.
#
unset CDPATH

# function to do a DEBUG and non-DEBUG build. Needed because we might
# need to do another for the source build, and since we only deliver DEBUG or
# non-DEBUG packages.

normal_build() {

	# timestamp the start of a nightly build; the findunref tool uses it.
	touch $SRC/.build.tstamp

	# non-DEBUG build begins

	if [ "$F_FLAG" = "n" ]; then
		export INTERNAL_RELEASE_BUILD ; INTERNAL_RELEASE_BUILD=
		export RELEASE_BUILD ; RELEASE_BUILD=
		unset EXTRA_OPTIONS
		unset EXTRA_CFLAGS

		build non-DEBUG -nd

		if [ "$build_ok" = "y" -a "$X_FLAG" = "y" -a "$p_FLAG" = "y" ]; then
			copy_ihv_pkgs non-DEBUG -nd
		fi
	else
		echo "\n==== No non-DEBUG build ====\n" >> $LOGFILE
	fi

	# non-DEBUG build ends

	# DEBUG build begins

	if [ "$D_FLAG" = "y" ]; then

		export INTERNAL_RELEASE_BUILD ; INTERNAL_RELEASE_BUILD=
		unset RELEASE_BUILD
		unset EXTRA_OPTIONS
		unset EXTRA_CFLAGS

		build DEBUG ""

		if [ "$build_ok" = "y" -a "$X_FLAG" = "y" -a "$p_FLAG" = "y" ]; then
			copy_ihv_pkgs DEBUG ""
		fi

	else
		echo "\n==== No DEBUG build ====\n" >> $LOGFILE
	fi

	# DEBUG build ends
}

filelist() {
	if  [ $# -ne 2 ]; then
		echo "usage: filelist DESTDIR PATTERN"
		exit 1;
	fi
	DEST=$1
	PATTERN=$2
	cd ${DEST}

	OBJFILES=${ORIG_SRC}/xmod/obj_files
	if [ ! -f ${OBJFILES} ]; then
		return;
	fi
	for i in `grep -v '^#' ${ORIG_SRC}/xmod/obj_files | \
	    grep ${PATTERN} | cut -d: -f2 | tr -d ' \t'`
	do
		# wildcard expansion
		for j in $i
		do
			if [ -f "$j" ]; then
				echo $j
			fi
			if [ -d "$j" ]; then
				echo $j
			fi
		done
	done | sort | uniq
}

# function to save off binaries after a full build for later
# restoration
save_binaries() {
	# save off list of binaries
	echo "\n==== Saving binaries from build at `date` ====\n" | \
	    tee -a $mail_msg_file >> $LOGFILE
	rm -f ${BINARCHIVE}
	cd ${CODEMGR_WS}
	filelist ${CODEMGR_WS} '^preserve:' >> $LOGFILE
	filelist ${CODEMGR_WS} '^preserve:' | \
	    cpio -ocB 2>/dev/null | compress \
	    > ${BINARCHIVE}
}

# delete files
hybridize_files() {
	if  [ $# -ne 2 ]; then
		echo "usage: hybridize_files DESTDIR MAKE_TARGET"
		exit 1;
	fi

	DEST=$1
	MAKETARG=$2

	echo "\n==== Hybridizing files at `date` ====\n" | \
	    tee -a $mail_msg_file >> $LOGFILE
	for i in `filelist ${DEST} '^delete:'`
	do
		echo "removing ${i}." | tee -a $mail_msg_file >> $LOGFILE
		rm -rf "${i}"
	done
	for i in `filelist ${DEST} '^hybridize:' `
	do
		echo "hybridizing ${i}." | tee -a $mail_msg_file >> $LOGFILE
		rm -f ${i}+
		sed -e "/^# HYBRID DELETE START/,/^# HYBRID DELETE END/d" \
		    < ${i} > ${i}+
		mv ${i}+ ${i}
	done
}

# restore binaries into the proper source tree.
restore_binaries() {
	if  [ $# -ne 2 ]; then
		echo "usage: restore_binaries DESTDIR MAKE_TARGET"
		exit 1;
	fi

	DEST=$1
	MAKETARG=$2

	echo "\n==== Restoring binaries to ${MAKETARG} at `date` ====\n" | \
	    tee -a $mail_msg_file >> $LOGFILE
	cd ${DEST}
	zcat ${BINARCHIVE} | \
	    cpio -idmucvB 2>/dev/null | tee -a $mail_msg_file >> ${LOGFILE}
}

# rename files we save binaries of
rename_files() {
	if  [ $# -ne 2 ]; then
		echo "usage: rename_files DESTDIR MAKE_TARGET"
		exit 1;
	fi

	DEST=$1
	MAKETARG=$2
	echo "\n==== Renaming source files in ${MAKETARG} at `date` ====\n" | \
	    tee -a $mail_msg_file >> $LOGFILE
	for i in `filelist ${DEST} '^rename:'`
	do
		echo ${i} | tee -a $mail_msg_file >> ${LOGFILE}
		rm -f ${i}.export
		mv ${i} ${i}.export
	done
}

# function to create the export/crypt source tree
# usage: clone_source CODEMGR_WS DESTDIR MAKE_TARGET

clone_source() {

	if  [ $# -ne 3 ]; then
		echo "usage: clone_source CODEMGR_WS DESTDIR MAKE_TARGET"
		exit 1;
	fi
	WS=$1
	DEST=$2
	MAKETARG=$3

	echo "\n==== Creating ${DEST} source from ${WS} (${MAKETARG}) ====\n" | \
	    tee -a $mail_msg_file >> $LOGFILE

	echo "cleaning out ${DEST}." >> $LOGFILE
	rm -rf "${DEST}" >> $LOGFILE 2>&1

	mkdir -p ${DEST}
	cd ${WS}

	echo "creating ${DEST}." >> $LOGFILE
	find usr -name 's\.*' -a -type f -print | \
	    sed -e 's,SCCS\/s.,,' | \
	    grep -v '/\.del-*' | \
	    cpio -pd ${DEST} >>$LOGFILE 2>&1

	SRC=${DEST}/usr/src

	cd $SRC
	rm -f ${MAKETARG}.out
	echo "making ${MAKETARG} in ${SRC}." >> $LOGFILE
	/bin/time $MAKE -e ${MAKETARG} 2>&1 | \
	    tee -a $SRC/${MAKETARG}.out >> $LOGFILE
	echo "\n==== ${MAKETARG} build errors ====\n" >> $mail_msg_file
	egrep ":" $SRC/${MAKETARG}.out | \
		egrep -e "(^${MAKE}:|[ 	]error[: 	\n])" | \
		egrep -v "Ignoring unknown host" | \
		egrep -v "warning" >> $mail_msg_file

	echo "clearing state files." >> $LOGFILE
	find . -name '.make*' -exec rm -f {} \;

	cd ${DEST}
	if [ "${MAKETARG}" = "CRYPT_SRC" ]; then
		rm -f ${CODEMGR_WS}/crypt_files.cpio.Z
		echo "\n==== xmod/cry_files that don't exist ====\n" | \
		    tee -a $mail_msg_file >> $LOGFILE
		CRYPT_FILES=${WS}/usr/src/xmod/cry_files
		for i in `cat ${CRYPT_FILES}`
		do
			# make sure the files exist
			if [ -f "$i" ]; then
				continue
			fi
			if [ -d "$i" ]; then
				continue
			fi
			echo "$i" | tee -a $mail_msg_file >> $LOGFILE
		done
		find `cat ${CRYPT_FILES}` -print 2>/dev/null | \
		    cpio -ocB 2>/dev/null | \
		    compress > ${CODEMGR_WS}/crypt_files.cpio.Z
	fi

	if [ "${MAKETARG}" = "EXPORT_SRC" ]; then
		# rename first, since we might restore a file
		# of the same name (mapfiles)
		rename_files ${EXPORT_SRC} EXPORT_SRC
		if [ "$SH_FLAG" = "y" ]; then
			hybridize_files ${EXPORT_SRC} EXPORT_SRC
		fi
	fi

	# save the cleartext
	echo "\n==== Creating ${MAKETARG}.cpio.Z ====\n" | \
	    tee -a $mail_msg_file >> $LOGFILE
	cd ${DEST}
	rm -f ${MAKETARG}.cpio.Z
	find usr -depth -print | \
	    grep -v usr/src/${MAKETARG}.out | \
	    cpio -ocB 2>/dev/null | \
	    compress > ${CODEMGR_WS}/${MAKETARG}.cpio.Z
	if [ "${MAKETARG}" = "EXPORT_SRC" ]; then
		restore_binaries ${EXPORT_SRC} EXPORT_SRC
	fi

	if [ "${MAKETARG}" = "CRYPT_SRC" ]; then
		restore_binaries ${CRYPT_SRC} CRYPT_SRC
	fi

}

# function to do the build.
# usage: build LABEL SUFFIX

build() {

	if  [ $# -ne 2 ]; then
		echo "usage: build LABEL SUFFIX"
		exit 1;
	fi

	LABEL=$1
	SUFFIX=$2
	INSTALLOG=install${SUFFIX}-${MACH}
	NOISE=noise${SUFFIX}-${MACH}
	CPIODIR=${CPIODIR_ORIG}${SUFFIX}
	PKGARCHIVE=${PKGARCHIVE_ORIG}${SUFFIX}
	if [ "$SPARC_RM_PKGARCHIVE_ORIG" ]; then
		SPARC_RM_PKGARCHIVE=${SPARC_RM_PKGARCHIVE_ORIG}${SUFFIX}
	fi

	#remove old logs
	OLDINSTALLOG=install${SUFFIX}
	OLDNOISE=noise${SUFFIX}
	rm -f $SRC/${OLDINSTALLOG}.out
	rm -f $SRC/${OLDNOISE}.ref
	if [ -f $SRC/${OLDNOISE}.out ]; then
		mv $SRC/${OLDNOISE}.out $SRC/${NOISE}.ref
	fi

	this_build_ok=y
	#
	#	Build OS-Networking source
	#
	echo "\n==== Building OS-Net source at `date` ($LABEL) ====\n" \
		>> $LOGFILE

	rm -f $SRC/${INSTALLOG}.out
	cd $SRC
	/bin/time $MAKE -e install 2>&1 | \
	    tee -a $SRC/${INSTALLOG}.out >> $LOGFILE

	echo "\n==== SCCS Noise ($LABEL) ====\n" >> $mail_msg_file

	egrep 'sccs(check|  get)' $SRC/${INSTALLOG}.out >> $mail_msg_file

	echo "\n==== Build errors ($LABEL) ====\n" >> $mail_msg_file
	egrep ":" $SRC/${INSTALLOG}.out |
		egrep -e "(^${MAKE}:|[ 	]error[: 	\n])" | \
		egrep -v "Ignoring unknown host" | \
		egrep -v "cc .* -o error " | \
		egrep -v "warning" >> $mail_msg_file
	if [ "$?" = "0" ]; then
		build_ok=n
		this_build_ok=n
	fi
	grep "bootblock image is .* bytes too big" $SRC/${INSTALLOG}.out \
		>> $mail_msg_file
	if [ "$?" = "0" ]; then
		build_ok=n
		this_build_ok=n
	fi

	if [ "$W_FLAG" = "n" ]; then
		echo "\n==== Build warnings ($LABEL) ====\n" >>$mail_msg_file
		egrep -i warning: $SRC/${INSTALLOG}.out \
			| egrep -v '^tic:' \
			| egrep -v "symbol \`timezone' has differing types:" \
		        | egrep -v "parameter <PSTAMP> set to" \
			| egrep -v "Ignoring unknown host" \
			| egrep -v "redefining segment flags attribute for" \
			>> $mail_msg_file
	fi

	echo "\n==== Ended OS-Net source build at `date` ($LABEL) ====\n" \
		>> $LOGFILE

	echo "\n==== Elapsed build time ($LABEL) ====\n" >>$mail_msg_file
	tail -3  $SRC/${INSTALLOG}.out >>$mail_msg_file

	if [ "$i_FLAG" = "n" -a "$W_FLAG" = "n" ]; then
		rm -f $SRC/${NOISE}.ref
		if [ -f $SRC/${NOISE}.out ]; then
			mv $SRC/${NOISE}.out $SRC/${NOISE}.ref
		fi
		grep : $SRC/${INSTALLOG}.out \
			| egrep -v '^/' \
			| egrep -v '^(Start|Finish|real|user|sys|./bld_awk)' \
			| egrep -v '^tic:' \
			| egrep -v '^mcs' \
			| egrep -v '^LD_LIBRARY_PATH=' \
			| egrep -v 'ar: creating' \
			| egrep -v 'ar: writing' \
			| egrep -v 'conflicts:' \
			| egrep -v ':saved created' \
			| egrep -v '^stty.*c:' \
			| egrep -v '^mfgname.c:' \
			| egrep -v '^uname-i.c:' \
			| egrep -v '^volumes.c:' \
			| egrep -v '^lint library construction:' \
			| egrep -v 'tsort: INFORM:' \
			| egrep -v 'stripalign:' \
			| egrep -v 'chars, width' \
			| egrep -v "symbol \`timezone' has differing types:" \
			| egrep -v 'PSTAMP' \
			| egrep -v '|%WHOANDWHERE%|' \
			| egrep -v '^Manifying' \
			| egrep -v 'Ignoring unknown host' \
			| egrep -v 'Processing method:' \
			| egrep -v '^Writing' \
			| egrep -v 'spellin1:' \
			| egrep -v '^adding:' \
			| egrep -v "^echo 'msgid" \
			| egrep -v '^echo ' \
			| egrep -v '\.c:$' \
			| egrep -v '^Adding file:' \
			| egrep -v 'CLASSPATH=' \
			| egrep -v '\/var\/mail\/:saved' \
			| egrep -v -- '-DUTS_VERSION=' \
			| egrep -v '^Running Mkbootstrap' \
			| egrep -v '^Applet length read:' \
			| egrep -v 'bytes written:' \
			| egrep -v '^File:SolarisAuthApplet.bin' \
			| egrep -v -i 'jibversion' \
			| egrep -v '^Output size:' \
			| egrep -v '^Solo size statistics:' \
			| egrep -v '^Using ROM API Version' \
			| egrep -v '^Zero Signature length:' \
			| egrep -v '^Note \(probably harmless\):' \
			| egrep -v '::' \
			| egrep -v -- '-xcache' \
			| egrep -v '^\+' \
			| egrep -v '^cc1: note: -fwritable-strings' \
			| egrep -v 'svccfg-native -s svc:/' \
			| sort | uniq >$SRC/${NOISE}.out
		if [ ! -f $SRC/${NOISE}.ref ]; then
			cp $SRC/${NOISE}.out $SRC/${NOISE}.ref
		fi
		echo "\n==== Build noise differences ($LABEL) ====\n" \
			>>$mail_msg_file
		diff $SRC/${NOISE}.ref $SRC/${NOISE}.out >>$mail_msg_file
	fi

	#
	#	Create cpio archives for preintegration testing (PIT)
	#
	if [ "$a_FLAG" = "y" -a "$this_build_ok" = "y" ]; then
		echo "\n==== Creating $LABEL cpio archives at `date` ====\n" \
			>> $LOGFILE
		makebfu_file="${TMPDIR}/makebfu"
		rm -f ${makebfu_file}
		makebfu 2>&1 | \
			tee -a ${makebfu_file} >> $LOGFILE
		echo "\n==== cpio archives build errors ($LABEL) ====\n" \
			>> $mail_msg_file
		grep -v "^Creating .* archive:" ${makebfu_file} | \
			grep -v "^Making" | \
			grep -v "^$" | \
			sort | uniq >> $mail_msg_file
		rm -f ${makebfu_file}
		# hack for test folks
		if [ -z "`echo $PARENT_WS|egrep '^\/ws\/'`" ]; then
			X=/net/`uname -n`${CPIODIR}
		else
			X=${CPIODIR}
		fi
		echo "Archive_directory: ${X}" >${TMPDIR}/f
		cp ${TMPDIR}/f ${CPIODIR}/../../.${MACH}_wgtrun
		rm -f ${TMPDIR}/f

	else
		echo "\n==== Not creating $LABEL cpio archives ====\n" \
			>> $LOGFILE
	fi

	#
	#	Building Packages
	#
	if [ "$p_FLAG" = "y" -a "$this_build_ok" = "y" ]; then
		echo "\n==== Creating $LABEL packages at `date` ====\n" \
			>> $LOGFILE
		rm -f $SRC/pkgdefs/${INSTALLOG}.out
		echo "Clearing out $PKGARCHIVE ..." >> $LOGFILE
		rm -rf $PKGARCHIVE
		mkdir -p $PKGARCHIVE

		#
		# Optional build of sparc realmode on i386
		#
		if [ "$MACH" = "i386" ] && [ "${SPARC_RM_PKGARCHIVE}" ]; then
			echo "Clearing out ${SPARC_RM_PKGARCHIVE} ..." \
				>> $LOGFILE
			rm -rf ${SPARC_RM_PKGARCHIVE}
			mkdir -p ${SPARC_RM_PKGARCHIVE}
		fi

		cd $SRC/pkgdefs
		$MAKE -e install 2>&1 | \
			tee -a $SRC/pkgdefs/${INSTALLOG}.out >> $LOGFILE
		echo "\n==== Package build errors ($LABEL) ====\n" \
			>> $mail_msg_file
		egrep "${MAKE}|ERROR|WARNING" $SRC/pkgdefs/${INSTALLOG}.out | \
			grep ':' | \
			grep -v PSTAMP | \
			egrep -v "Ignoring unknown host" \
			>> $mail_msg_file
	else
		echo "\n==== Not creating $LABEL packages ====\n" >> $LOGFILE
	fi
}

dolint() {

	#
	# Arg. 2 is a flag to turn on/off the lint diff output
	#
	dl_usage="Usage: dolint /dir y|n"

	if [ $# -ne 2 ]; then
		echo $dl_usage
		exit 1
	fi

	if [ ! -d "$1" ]; then
		echo $dl_usage
		exit 1
	fi

	if [ "$2" != "y" -a "$2" != "n" ]; then
		echo $dl_usage
		exit 1
	fi

	lintdir=$1
	dodiff=$2
	base=`basename $lintdir`
	LINTOUT=$lintdir/lint-${MACH}.out
	LINTNOISE=$lintdir/lint-noise-${MACH}

	export INTERNAL_RELEASE_BUILD ; INTERNAL_RELEASE_BUILD=
	unset RELEASE_BUILD
	unset EXTRA_OPTIONS
	unset EXTRA_CFLAGS

	#
	#	'$MAKE lint' in $lintdir
	#
	echo "\n==== Begin '$MAKE lint' of $base at `date` ====\n" >> $LOGFILE

	# remove old lint.out
	rm -f $lintdir/lint.out $lintdir/lint-noise.out
	if [ -f $lintdir/lint-noise.ref ]; then
		mv $lintdir/lint-noise.ref ${LINTNOISE}.ref
	fi

	rm -f $LINTOUT
	cd $lintdir
	#
	# Remove all .ln files to ensure a full reference file
	#
	rm -f Nothing_to_remove \
	    `find . -name SCCS -prune -o -type f -name '*.ln' -print `

	/bin/time $MAKE -ek lint 2>&1 | \
	    tee -a $LINTOUT >> $LOGFILE
	echo "\n==== '$MAKE lint' of $base ERRORS ====\n" >> $mail_msg_file
	grep "$MAKE:" $LINTOUT |
		egrep -v "Ignoring unknown host" \
		>> $mail_msg_file

	echo "\n==== Ended '$MAKE lint' of $base at `date` ====\n" >> $LOGFILE

	echo "\n==== Elapsed time of '$MAKE lint' of $base ====\n" \
		>>$mail_msg_file
	tail -3  $LINTOUT >>$mail_msg_file

	rm -f ${LINTNOISE}.ref
	if [ -f ${LINTNOISE}.out ]; then
		mv ${LINTNOISE}.out ${LINTNOISE}.ref
	fi
        grep : $LINTOUT | \
		egrep -v '^(real|user|sys)' |
		egrep -v '(library construction)' | \
		egrep -v ': global crosschecks' | \
		egrep -v 'Ignoring unknown host' | \
		egrep -v '\.c:$' | \
		sort | uniq > ${LINTNOISE}.out
	if [ ! -f ${LINTNOISE}.ref ]; then
		cp ${LINTNOISE}.out ${LINTNOISE}.ref
	fi
	if [ "$dodiff" != "n" ]; then
		echo "\n==== lint warnings $base ====\n" \
			>>$mail_msg_file
		# should be none, though there are a few that were filtered out
		# above
		egrep -i '(warning|lint):' ${LINTNOISE}.out \
			| sort | uniq >> $mail_msg_file
		echo "\n==== lint noise differences $base ====\n" \
			>> $mail_msg_file
		diff ${LINTNOISE}.ref ${LINTNOISE}.out \
			>> $mail_msg_file
	fi
}

# Install proto area from IHV build

copy_ihv_proto() {

	echo "\n==== Installing IHV proto area ====\n" \
		>> $LOGFILE
	if [ -d "$IA32_IHV_ROOT" ]; then
		if [ ! -d "$ROOT" ]; then
			echo "mkdir -p $ROOT" >> $LOGFILE
			mkdir -p $ROOT
		fi
		echo "copying $IA32_IHV_ROOT to $ROOT\n" >> $LOGFILE
		cd $IA32_IHV_ROOT
		tar -cf - . | (cd $ROOT; umask 0; tar xpf - ) 2>&1 >> $LOGFILE
	else
		echo "$IA32_IHV_ROOT: not found" >> $LOGFILE
	fi
}

# Install IHV packages in PKGARCHIVE

copy_ihv_pkgs() {

	if  [ $# -ne 2 ]; then
		echo "usage: copy_ihv_pkgs LABEL SUFFIX"
		exit 1;
	fi

	LABEL=$1
	SUFFIX=$2
	# always use non-DEBUG IHV packages
	IA32_IHV_PKGS=${IA32_IHV_PKGS_ORIG}-nd
	PKGARCHIVE=${PKGARCHIVE_ORIG}${SUFFIX}

	echo "\n==== Installing IHV packages from $IA32_IHV_PKGS ($LABEL) ====\n" \
		>> $LOGFILE
	if [ -d "$IA32_IHV_PKGS" ]; then
		cd $IA32_IHV_PKGS
		tar -cf - * | \
		   (cd $PKGARCHIVE; umask 0; tar xpf - ) 2>&1 >> $LOGFILE
	else
		echo "$IA32_IHV_PKGS: not found" >> $LOGFILE
	fi

	echo "\n==== Installing IHV packages from $IA32_IHV_BINARY_PKGS ($LABEL) ====\n" \
		>> $LOGFILE
	if [ -d "$IA32_IHV_BINARY_PKGS" ]; then
		cd $IA32_IHV_BINARY_PKGS
		tar -cf - * | \
		    (cd $PKGARCHIVE; umask 0; tar xpf - ) 2>&1 >> $LOGFILE
	else
		echo "$IA32_IHV_BINARY_PKGS: not found" >> $LOGFILE
	fi
}

build_tools() {

	if  [ $# -ne 1 ]; then
		echo "usage: build_tools DESTROOT"
		exit 1;
	fi

	DESTROOT=$1

	INSTALLOG=install-${MACH}

	echo "\n==== Building tools at `date` ====\n" \
		>> $LOGFILE

	rm -f ${TOOLS}/${INSTALLOG}.out
	cd ${TOOLS}
	/bin/time $MAKE ROOT=${DESTROOT} -e install 2>&1 | \
	    tee -a ${TOOLS}/${INSTALLOG}.out >> $LOGFILE

	echo "\n==== Tools build errors ====\n" >> $mail_msg_file

	egrep ":" ${TOOLS}/${INSTALLOG}.out |
		egrep -e "(${MAKE}:|[ 	]error[: 	\n])" | \
		egrep -v "Ignoring unknown host" | \
		egrep -v warning >> $mail_msg_file
	if [ "$?" != "0" ]; then
		STABS=${DESTROOT}/opt/onbld/bin/${MACH}/stabs
		export STABS
		CTFSTABS=${DESTROOT}/opt/onbld/bin/${MACH}/ctfstabs
		export CTFSTABS
		GENOFFSETS=${DESTROOT}/opt/onbld/bin/genoffsets
		export GENOFFSETS

		CTFCONVERT=${DESTROOT}/opt/onbld/bin/${MACH}/ctfconvert
		export CTFCONVERT
		CTFMERGE=${DESTROOT}/opt/onbld/bin/${MACH}/ctfmerge
		export CTFMERGE

		CTFCVTPTBL=${DESTROOT}/opt/onbld/bin/ctfcvtptbl
		export CTFCVTPTBL
		CTFFINDMOD=${DESTROOT}/opt/onbld/bin/ctffindmod
		export CTFFINDMOD

		if [ "$VERIFY_ELFSIGN" = "y" ]; then
			ELFSIGN=${DESTROOT}/opt/onbld/bin/elfsigncmp
		else
			ELFSIGN=${DESTROOT}/opt/onbld/bin/${MACH}/elfsign
		fi
		export ELFSIGN

		PATH="${DESTROOT}/opt/onbld/bin/${MACH}:${PATH}"
		PATH="${DESTROOT}/opt/onbld/bin:${PATH}"
		export PATH

		echo "\n==== New environment settings. ====\n" >> $LOGFILE
		echo "STABS=${STABS}" >> $LOGFILE
		echo "CTFSTABS=${CTFSTABS}" >> $LOGFILE
		echo "CTFCONVERT=${CTFCONVERT}" >> $LOGFILE
		echo "CTFMERGE=${CTFMERGE}" >> $LOGFILE
		echo "CTFCVTPTBL=${CTFCVTPTBL}" >> $LOGFILE
		echo "CTFFINDMOD=${CTFFINDMOD}" >> $LOGFILE
		echo "ELFSIGN=${ELFSIGN}" >> $LOGFILE
		echo "PATH=${PATH}" >> $LOGFILE
	fi
}

staffer() {
	if [ $ISUSER -ne 0 ]; then
		"$@"
	else
		arg="\"$1\""
		shift
		for i
		do
			arg="$arg \"$i\""
		done
		eval su $STAFFER -c \'$arg\'
	fi
}

#
# Verify that the closed tree is present if it needs to be.
# Sets CLOSED_IS_PRESENT for future use.
#
check_closed_tree() {
	if [ -z "$CLOSED_IS_PRESENT" ]; then
		if [ -d $SRC/../closed ]; then
			CLOSED_IS_PRESENT="yes"
		else
			CLOSED_IS_PRESENT="no"
		fi
		export CLOSED_IS_PRESENT
	fi
	if [[ "$CLOSED_IS_PRESENT" = no && ! -d "$ON_CLOSED_BINS" ]]; then
		#
		# If it's an old (pre-split) tree or an empty
		# workspace, don't complain.
		#
		if grep -s CLOSED_BUILD $SRC/Makefile.master > /dev/null; then
			echo "If the closed sources are not present," \
			    "ON_CLOSED_BINS"
			echo "must point to the closed binaries tree."
			exit 1
		fi
	fi
}

obsolete_build() {
    	echo "WARNING: Obsolete $1 build requested; request will be ignored"
}


MACH=`uname -p`

if [ "$OPTHOME" = "" ]; then
	OPTHOME=/opt
	export OPTHOME
fi
if [ "$TEAMWARE" = "" ]; then
	TEAMWARE=$OPTHOME/teamware
	export TEAMWARE
fi

USAGE='Usage: nightly [-in] [-V VERS ] [ -S E|D|H ] <env_file>

Where:
	-i	Fast incremental options (no clobber, lint, check)
	-n      Do not do a bringover
	-V VERS set the build version string to VERS
	-S	Build a variant of the source product
		E - build exportable source
		D - build domestic source (exportable + crypt)
		H - build hybrid source (binaries + deleted source)

	<env_file>  file in Bourne shell syntax that sets and exports
	variables that configure the operation of this script and many of
	the scripts this one calls. If <env_file> does not exist,
	it will be looked for in $OPTHOME/onbld/env.

non-DEBUG is the default build type. Build options can be set in the
NIGHTLY_OPTIONS variable in the <env_file> as follows:

	-A	check for ABI differences in .so files
	-C	check for cstyle/hdrchk errors
	-D	do a build with DEBUG on
	-F	do _not_ do a non-DEBUG build
	-G	gate keeper default group of options (-au)
	-I	integration engineer default group of options (-ampu)
	-M	do not run pmodes (safe file permission checker)
	-N	do not run protocmp
	-R	default group of options for building a release (-mp)
	-U	update proto area in the parent
	-V VERS set the build version string to VERS
	-X	copy x86 IHV proto area
	-a	create cpio archives
	-f	find unreferenced files
	-i	do an incremental build (no "make clobber")
	-l	do "make lint" in $LINTDIRS (default: $SRC y)
	-m	send mail to $MAILTO at end of build
	-n      do not do a bringover
	-o	build using root privileges to set OWNER/GROUP (old style)
	-p	create packages
	-r	check ELF runtime attributes in the proto area
	-t	build and use the tools in $SRC/tools
	-u	update proto_list_$MACH and friends in the parent workspace;
		when used with -f, also build an unrefmaster.out in the parent
	-w	report on differences between previous and current proto areas
	-z	compress cpio archives with gzip
	-W	Do not report warnings (freeware gate ONLY)
	-S	Build a variant of the source product
		E - build exportable source
		D - build domestic source (exportable + crypt)
		H - build hybrid source (binaries + deleted source)
'
#
#	-x	less public handling of xmod source for the source product
#
#	A log file will be generated under the name $LOGFILE
#	for partially completed build and log.`date '+%F'`
#	in the same directory for fully completed builds.
#

# default values for low-level FLAGS; G I R are group FLAGS
A_FLAG=n
a_FLAG=n
C_FLAG=n
F_FLAG=n
f_FLAG=n
D_FLAG=n
P_FLAG=n
T_FLAG=n
n_FLAG=n
o_FLAG=n
i_FLAG=n; i_CMD_LINE_FLAG=n
l_FLAG=n
m_FLAG=n
p_FLAG=n
r_FLAG=n
t_FLAG=n
u_FLAG=n
U_FLAG=n
V_FLAG=n
M_FLAG=n
N_FLAG=n
z_FLAG=n
w_FLAG=n
W_FLAG=n
SE_FLAG=n
SD_FLAG=n
SH_FLAG=n
X_FLAG=n
#
XMOD_OPT=
#
build_ok=y
#
# examine arguments
#

OPTIND=1
while getopts inV:S:t FLAG
do
	case $FLAG in
	  i )	i_FLAG=y; i_CMD_LINE_FLAG=y
		;;
	  n )	n_FLAG=y
		;;
	  V )	V_FLAG=y
		V_ARG="$OPTARG"
		;;
	  S )
		if [ "$SE_FLAG" = "y" -o "$SD_FLAG" = "y" -o "$SH_FLAG" = "y" ]; then
			echo "Can only build one source variant at a time."
			exit 1
		fi
		if [ "${OPTARG}" = "E" ]; then
			SE_FLAG=y
		elif [ "${OPTARG}" = "D" ]; then
			SD_FLAG=y
		elif [ "${OPTARG}" = "H" ]; then
			SH_FLAG=y
		else
			echo "$USAGE"
			exit 1
		fi
		;;
	  t )	t_FLAG=y
		;;
	 \? )	echo "$USAGE"
		exit 1
		;;
	esac
done

# correct argument count after options
shift `expr $OPTIND - 1`

# test that the path to the environment-setting file was given
if [ $# -ne 1 ]; then
	echo "$USAGE"
	exit 1
fi

# check if user is running nightly as root
# ISUSER is set non-zero if an ordinary user runs nightly, or is zero
# when root invokes nightly.
/usr/bin/id | grep '^uid=0(' >/dev/null 2>&1
ISUSER=$?;	export ISUSER

#
# force locale to C
LC_COLLATE=C;	export LC_COLLATE
LC_CTYPE=C;	export LC_CTYPE
LC_MESSAGES=C;	export LC_MESSAGES
LC_MONETARY=C;	export LC_MONETARY
LC_NUMERIC=C;	export LC_NUMERIC
LC_TIME=C;	export LC_TIME

# clear environment variables we know to be bad for the build
unset LD_OPTIONS
unset LD_AUDIT		LD_AUDIT_32		LD_AUDIT_64
unset LD_BIND_NOW	LD_BIND_NOW_32		LD_BIND_NOW_64
unset LD_BREADTH	LD_BREADTH_32		LD_BREADTH_64
unset LD_CONFIG		LD_CONFIG_32		LD_CONFIG_64
unset LD_DEBUG		LD_DEBUG_32		LD_DEBUG_64
unset LD_DEMANGLE	LD_DEMANGLE_32		LD_DEMANGLE_64
unset LD_FLAGS		LD_FLAGS_32		LD_FLAGS_64
unset LD_LIBRARY_PATH	LD_LIBRARY_PATH_32	LD_LIBRARY_PATH_64
unset LD_LOADFLTR	LD_LOADFLTR_32		LD_LOADFLTR_64
unset LD_NOAUDIT	LD_NOAUDIT_32		LD_NOAUDIT_64
unset LD_NOAUXFLTR	LD_NOAUXFLTR_32		LD_NOAUXFLTR_64
unset LD_NOCONFIG	LD_NOCONFIG_32		LD_NOCONFIG_64
unset LD_NODIRCONFIG	LD_NODIRCONFIG_32	LD_NODIRCONFIG_64
unset LD_NODIRECT	LD_NODIRECT_32		LD_NODIRECT_64
unset LD_NOLAZYLOAD	LD_NOLAZYLOAD_32	LD_NOLAZYLOAD_64
unset LD_NOOBJALTER	LD_NOOBJALTER_32	LD_NOOBJALTER_64
unset LD_NOVERSION	LD_NOVERSION_32		LD_NOVERSION_64
unset LD_ORIGIN		LD_ORIGIN_32		LD_ORIGIN_64
unset LD_PRELOAD	LD_PRELOAD_32		LD_PRELOAD_64
unset LD_PROFILE	LD_PROFILE_32		LD_PROFILE_64

unset CONFIG
unset GROUP
unset OWNER
unset REMOTE
unset ENV
unset ARCH
unset CLASSPATH
unset NAME

#
#	Setup environmental variables
#
if [ -f $1 ]; then
	if [[ $1 = */* ]]; then
		. $1
	else
		. ./$1
	fi
else
	if [ -f $OPTHOME/onbld/env/$1 ]; then
		. $OPTHOME/onbld/env/$1
	else
		echo "Cannot find env file as either $1 or $OPTHOME/onbld/env/$1"
		exit 1
	fi
fi

#
# place ourselves in a new task, respecting BUILD_PROJECT if set.
#
if [ -z "$BUILD_PROJECT" ]; then
	/usr/bin/newtask -c $$
else
	/usr/bin/newtask -c $$ -p $BUILD_PROJECT
fi

ps -o taskid= -p $$ | read build_taskid
ps -o project= -p $$ | read build_project

#
# See if NIGHTLY_OPTIONS is set
#
if [ "$NIGHTLY_OPTIONS" = "" ]; then
	NIGHTLY_OPTIONS="-aBm"
fi

#
# If BRINGOVER_WS was not specified, let it default to CLONE_WS
#
if [ "$BRINGOVER_WS" = "" ]; then
	BRINGOVER_WS=$CLONE_WS
fi

#
# If BRINGOVER_FILES was not specified, default to usr
#
if [ "$BRINGOVER_FILES" = "" ]; then
	BRINGOVER_FILES="usr"
fi

#
# If the closed sources are not present, the closed binaries must be
# present for the build to succeed.  If there's no pointer to the
# closed binaries, flag that now, rather than forcing the user to wait
# a couple hours (or more) to find out.
#
orig_closed_is_present="$CLOSED_IS_PRESENT"
check_closed_tree

#
# Note: changes to the option letters here should also be applied to the
#	bldenv script.  `d' is listed for backward compatibility.
#
NIGHTLY_OPTIONS=-${NIGHTLY_OPTIONS#-}
OPTIND=1
while getopts ABDFNMPTCGIRafinlmoptuUxdrtwzWS:X FLAG $NIGHTLY_OPTIONS
do
	case $FLAG in
	  A )	A_FLAG=y
		;;
	  B )	D_FLAG=y
		;; # old version of D
	  F )	F_FLAG=y
		;;
	  D )	D_FLAG=y
		;;
	  P )	P_FLAG=y 
		;; # obsolete
	  T )	T_FLAG=y
		;; # obsolete
	  C )	C_FLAG=y
		;;
	  M )	M_FLAG=y
		;;
	  N )	N_FLAG=y
		;;
	  G )	a_FLAG=y
		u_FLAG=y
		;;
	  I )	a_FLAG=y
		m_FLAG=y
		p_FLAG=y
		u_FLAG=y
		;;
	  R )	m_FLAG=y
		p_FLAG=y
		;;
	  a )	a_FLAG=y
		;;
	  f )	f_FLAG=y
		;;
	  i )	i_FLAG=y
		;;
	  n )	n_FLAG=y
		;;
	  o )	o_FLAG=y
		;;
	  l )	l_FLAG=y
		;;
	  m )	m_FLAG=y
		;;
	  p )	p_FLAG=y
		;;
	  r )	r_FLAG=y
		;;
	  t )	t_FLAG=y
		;;
	  u )	u_FLAG=y
		;;
	  w )	w_FLAG=y
		;;
	  z )	z_FLAG=y
		;;
	  U )
		if [ -z "${PARENT_ROOT}" ]; then
			echo "PARENT_ROOT must be set if the U flag is" \
			    "present in NIGHTLY_OPTIONS."
			exit 1
		fi
		U_FLAG=y
		NIGHTLY_PARENT_ROOT=$PARENT_ROOT
		;;
	  x )	XMOD_OPT="-x"
		;;
	  W )	W_FLAG=y
		;;
	  S )
		if [ "$SE_FLAG" = "y" -o "$SD_FLAG" = "y" -o "$SH_FLAG" = "y" ]; then
			echo "Can only build one source variant at a time."
			exit 1
		fi
		if [ "${OPTARG}" = "E" ]; then
			SE_FLAG=y
		elif [ "${OPTARG}" = "D" ]; then
			SD_FLAG=y
		elif [ "${OPTARG}" = "H" ]; then
			SH_FLAG=y
		else
			echo "$USAGE"
			exit 1
		fi
		;;
	  X )	# now that we no longer need realmode builds, just
		# copy IHV packages.  only meaningful on x86.
		if [ "$MACH" = "i386" ]; then
			X_FLAG=y
		fi
		;;
	 \? )	echo "$USAGE"
		exit 1
		;;
	esac
done

if [ $ISUSER -ne 0 ]; then
	if [ "$o_FLAG" = "y" ]; then
		echo "Old-style build requires root permission."
		exit 1
	fi

	# Set default value for STAFFER, if needed.
	if [ -z "$STAFFER" -o "$STAFFER" = "nobody" ]; then
		STAFFER=`/usr/xpg4/bin/id -un`
		export STAFFER
	fi
fi

if [ -z "$MAILTO" -o "$MAILTO" = "nobody" ]; then
	MAILTO=$STAFFER
	export MAILTO
fi

PATH="$OPTHOME/onbld/bin:$OPTHOME/onbld/bin/${MACH}:/usr/ccs/bin"
PATH="$PATH:$OPTHOME/SUNWspro/bin:$TEAMWARE/bin:/usr/bin:/usr/sbin:/usr/ucb"
PATH="$PATH:/usr/openwin/bin:/usr/sfw/bin:/opt/sfw/bin:."
export PATH

# roots of source trees, both relative to $SRC and absolute.
relsrcdirs="."
if [[ -d $SRC/../closed && "$CLOSED_IS_PRESENT" != no ]]; then
	relsrcdirs="$relsrcdirs ../closed"
fi
abssrcdirs=""
for d in $relsrcdirs; do
	abssrcdirs="$abssrcdirs $SRC/$d"
done

unset CH
if [ "$o_FLAG" = "y" ]; then
# root invoked old-style build -- make sure it works as it always has
# by exporting 'CH'.  The current Makefile.master doesn't use this, but
# the old ones still do.
	PROTOCMPTERSE="protocmp.terse"
	CH=
	export CH
else
	PROTOCMPTERSE="protocmp.terse -gu"
fi
POUND_SIGN="#"

# we export POUND_SIGN to speed up the build process -- prevents evaluation of
# the Makefile.master definitions.
export o_FLAG X_FLAG POUND_SIGN

maketype="distributed"
MAKE=dmake
# get the dmake version string alone
DMAKE_VERSION=$( $MAKE -v )
DMAKE_VERSION=${DMAKE_VERSION#*: }
# focus in on just the dotted version number alone
DMAKE_MAJOR=$( echo $DMAKE_VERSION | \
	sed -e 's/.*\<\([^.]*\.[^   ]*\).*$/\1/' )
# extract the second (or final) integer
DMAKE_MINOR=${DMAKE_MAJOR#*.}
DMAKE_MINOR=${DMAKE_MINOR%%.*}
# extract the first integer
DMAKE_MAJOR=${DMAKE_MAJOR%%.*}
CHECK_DMAKE=${CHECK_DMAKE:-y}
# x86 was built on the 12th, sparc on the 13th.
if [ "$CHECK_DMAKE" = "y" -a \
     "$DMAKE_VERSION" != "Sun Distributed Make 7.3 2003/03/12" -a \
     "$DMAKE_VERSION" != "Sun Distributed Make 7.3 2003/03/13" -a \( \
     "$DMAKE_MAJOR" -lt 7 -o \
     "$DMAKE_MAJOR" -eq 7 -a "$DMAKE_MINOR" -lt 4 \) ]; then
	if [ -z "$DMAKE_VERSION" ]; then
		echo "$MAKE is missing."
		exit 1
	fi
	echo `whence $MAKE`" version is:"
	echo "  ${DMAKE_VERSION}"
	cat <<EOF

This version may not be safe for use.  Either set TEAMWARE to a better
path or (if you really want to use this version of dmake anyway), add
the following to your environment to disable this check:

  CHECK_DMAKE=n
EOF
	exit 1
fi
export PATH
export MAKE

if [ "${SUNWSPRO}" != "" ]; then
	PATH="${SUNWSPRO}/bin:$PATH"
	export PATH
fi

hostname=`uname -n`
if [ ! -f $HOME/.make.machines ]; then
	DMAKE_MAX_JOBS=4
else
	DMAKE_MAX_JOBS="`grep $hostname $HOME/.make.machines | \
	    tail -1 | awk -F= '{print $ 2;}'`"
	if [ "$DMAKE_MAX_JOBS" = "" ]; then
		DMAKE_MAX_JOBS=4
	fi
fi
DMAKE_MODE=parallel;
export DMAKE_MODE
export DMAKE_MAX_JOBS

if [ -z "${ROOT}" ]; then
	echo "ROOT must be set."
	exit 1
fi

if [ "$SE_FLAG" = "y" -o "$SD_FLAG" = "y" ]; then
        if [ -z "${EXPORT_SRC}" ]; then
		echo "EXPORT_SRC must be set for a source build."
		exit 1
	fi
        if [ -z "${CRYPT_SRC}" ]; then
		echo "CRYPT_SRC must be set for a source build."
		exit 1
	fi
fi

if [ "$SH_FLAG" = "y" ]; then
        if [ -z "${EXPORT_SRC}" ]; then
		echo "EXPORT_SRC must be set for a source build."
		exit 1
	fi
fi

#
# if -V flag was given, reset VERSION to V_ARG
#
if [ "$V_FLAG" = "y" ]; then
	VERSION=$V_ARG
fi

#
# Check for IHV root for copying ihv proto area
#
if [ "$X_FLAG" = "y" ]; then
        if [ "$IA32_IHV_ROOT" = "" ]; then
		echo "IA32_IHV_ROOT: must be set for copying ihv proto"
		args_ok=n
        fi
        if [ ! -d "$IA32_IHV_ROOT" ]; then
                echo "$IA32_IHV_ROOT: not found"
                args_ok=n
        fi
        if [ "$IA32_IHV_WS" = "" ]; then
		echo "IA32_IHV_WS: must be set for copying ihv proto"
		args_ok=n
        fi
        if [ ! -d "$IA32_IHV_WS" ]; then
                echo "$IA32_IHV_WS: not found"
                args_ok=n
        fi
fi

# Append source version
if [ "$SE_FLAG" = "y" ]; then
	VERSION="${VERSION}:EXPORT"
fi

if [ "$SD_FLAG" = "y" ]; then
	VERSION="${VERSION}:DOMESTIC"
fi

if [ "$SH_FLAG" = "y" ]; then
	VERSION="${VERSION}:MODIFIED_SOURCE_PRODUCT"
fi

TMPDIR="/tmp/nightly.tmpdir.$$"
export TMPDIR
rm -rf ${TMPDIR}
mkdir -p $TMPDIR || exit 1

#
# Keep elfsign's use of pkcs11_softtoken from looking in the user home
# directory, which doesn't always work.   Needed until all build machines
# have the fix for 6271754
#
SOFTTOKEN_DIR=$TMPDIR
export SOFTTOKEN_DIR

TOOLS=${SRC}/tools
TOOLS_PROTO=${TOOLS}/proto

unset   CFLAGS LD_LIBRARY_PATH LDFLAGS

# create directories that are automatically removed if the nightly script
# fails to start correctly
newdir() {
	dir=$1
	toadd=
	while [ ! -d $dir ]; do
		toadd="$dir $toadd"
		dir=`dirname $dir`
	done
	torm=
	newlist=
	for dir in $toadd; do
		if staffer mkdir $dir; then
			newlist="$ISUSER $dir $newlist"
			torm="$dir $torm"
		else
			[ -z "$torm" ] || staffer rmdir $torm
			return 1
		fi
	done
	newdirlist="$newlist $newdirlist"
	return 0
}
newdirlist=

[ -d $CODEMGR_WS ] || newdir $CODEMGR_WS || exit 1

# since this script assumes the build is from full source, it nullifies
# variables likely to have been set by a "ws" script; nullification
# confines the search space for headers and libraries to the proto area
# built from this immediate source.
ENVLDLIBS1=
ENVLDLIBS2=
ENVLDLIBS3=
ENVCPPFLAGS1=
ENVCPPFLAGS2=
ENVCPPFLAGS3=
ENVCPPFLAGS4=
PARENT_ROOT=

export ENVLDLIBS3 ENVCPPFLAGS1 ENVCPPFLAGS2 ENVCPPFLAGS3 ENVCPPFLAGS4 \
	PARENT_ROOT

ENVLDLIBS1="-L$ROOT/lib -L$ROOT/usr/lib"
ENVCPPFLAGS1="-I$ROOT/usr/include"

export ENVLDLIBS1 ENVLDLIBS2

CPIODIR_ORIG=$CPIODIR
PKGARCHIVE_ORIG=$PKGARCHIVE
IA32_IHV_PKGS_ORIG=$IA32_IHV_PKGS
if [ "$SPARC_RM_PKGARCHIVE" ]; then
	SPARC_RM_PKGARCHIVE_ORIG=$SPARC_RM_PKGARCHIVE
fi

#
# Juggle the logs and optionally send mail on completion.
#

logshuffle() {
    	LLOG="$ATLOG/log.`date '+%F'`"
	rm -rf $ATLOG/log.??`date '+%d'`
	rm -rf $ATLOG/log.????-??-`date '+%d'`
	if [ -f $LLOG -o -d $LLOG ]; then
	    	LLOG=$LLOG.$$
	fi
	mkdir $LLOG
	export LLOG

	if [ "$build_ok" = "y" ]; then
		mv $ATLOG/proto_list_${MACH} $LLOG

		if [ -f $TMPDIR/wsdiff.results ]; then
		    mv $TMPDIR/wsdiff.results $LLOG
		fi
	fi

	#
	# Now that we're about to send mail, it's time to check the noise
	# file.  In the event that an error occurs beyond this point, it will
	# be recorded in the nightly.log file, but nowhere else.  This would
	# include only errors that cause the copying of the noise log to fail
	# or the mail itself not to be sent.
	#

	exec >>$LOGFILE 2>&1
	if [ -s $build_noise_file ]; then
	    	echo "\n==== Nightly build noise ====\n" |
		    tee -a $LOGFILE >>$mail_msg_file
		cat $build_noise_file >>$LOGFILE
		cat $build_noise_file >>$mail_msg_file
		echo | tee -a $LOGFILE >>$mail_msg_file
	fi
	rm -f $build_noise_file

	case "$build_ok" in
		y)
			state=Completed
			;;
		i)
			state=Interrupted
			;;
		*)
	    		state=Failed
			;;
	esac
	NIGHTLY_STATUS=$state
	export NIGHTLY_STATUS

	if [ -n "$POST_NIGHTLY" ]; then
		echo "\n==== Running POST_NIGHTLY command:" \
		    "$POST_NIGHTLY ====\n" | tee -a $mail_msg_file >> $LOGFILE
		$POST_NIGHTLY $state 2>&1 | tee -a $mail_msg_file >> $LOGFILE
	fi

	cat $build_time_file $mail_msg_file > ${LLOG}/mail_msg
	if [ "$m_FLAG" = "y" ]; then
	    	cat $build_time_file $mail_msg_file |
		    /usr/bin/mailx -s \
	"Nightly ${MACH} Build of `basename ${CODEMGR_WS}` ${state}." \
			${MAILTO}
	fi

	if [ "$u_FLAG" = "y" -a "$build_ok" = "y" ]; then
	    	staffer cp ${LLOG}/mail_msg $PARENT_WS/usr/src/mail_msg-${MACH}
		staffer cp $LOGFILE $PARENT_WS/usr/src/nightly-${MACH}.log
	fi

	mv $LOGFILE $LLOG
}

#
#	Remove the locks and temporary files on any exit
#
cleanup() {
    	logshuffle

	[ -z "$lockfile" ] || staffer rm -f $lockfile
	[ -z "$atloglockfile" ] || rm -f $atloglockfile
	[ -z "$ulockfile" ] || staffer rm -f $ulockfile
	[ -z "$Ulockfile" ] || rm -f $Ulockfile

	set -- $newdirlist
	while [ $# -gt 0 ]; do
		ISUSER=$1 staffer rmdir $2
		shift; shift
	done
	rm -rf $TMPDIR
}

cleanup_signal() {
    	build_ok=i
	# this will trigger cleanup(), above.
	exit 1
}

trap cleanup 0
trap cleanup_signal 1 2 3 15

#
# Generic lock file processing -- make sure that the lock file doesn't
# exist.  If it does, it should name the build host and PID.  If it
# doesn't, then make sure we can create it.  Clean up locks that are
# known to be stale (assumes host name is unique among build systems
# for the workspace).
create_lock() {
	lockf=$1
	lockvar=$2
	if [ -f $lockf ]; then
		basews=`basename $CODEMGR_WS`
		if read host user pid < $lockf; then
			if [ "$host" != "$hostname" ]; then
				echo "$MACH build of $basews apparently" \
				    "already started by $user on $host as $pid."
			elif kill -s 0 $pid 2>/dev/null; then
				echo "$MACH build of $basews already started" \
				    "by $user as $pid."
			else
				# stale lock; clear it out and continue
				rm -f $lockf
			fi
		else
			echo "$MACH build of $basews already running."
		fi
	fi
	if [ -f $lockf ]; then
		echo "Lock file is $lockf."
		exit 1
	fi
	ldir=`dirname $lockf`
	[ -d $ldir ] || newdir $ldir || exit 1
	eval $lockvar=$lockf
	staffer sh -c "echo $hostname $STAFFER $$ > $lockf" || exit 1
}

# Ensure no other instance of this script is running on this host.
# LOCKNAME can be set in <env_file>, and is by default, but is not
# required due to the use of $ATLOG below.
if [ -n "$LOCKNAME" ]; then
	create_lock /tmp/$LOCKNAME "lockfile"
fi
#
# Create from one, two, or three other locks:
#	$ATLOG/nightly.lock
#		- protects against multiple builds in same workspace
#	$PARENT_WS/usr/src/nightly.$MACH.lock
#		- protects against multiple 'u' copy-backs
#	$NIGHTLY_PARENT_ROOT/nightly.lock
#		- protects against multiple 'U' copy-backs
#
# Overriding ISUSER to 1 causes the lock to be created as root if the
# script is run as root.  The default is to create it as $STAFFER.
ISUSER=1 create_lock $ATLOG/nightly.lock "atloglockfile"
if [ "$u_FLAG" = "y" ]; then
	create_lock $PARENT_WS/usr/src/nightly.$MACH.lock "ulockfile"
fi
if [ "$U_FLAG" = "y" ]; then
	# NIGHTLY_PARENT_ROOT is written as root if script invoked as root.
	ISUSER=1 create_lock $NIGHTLY_PARENT_ROOT/nightly.lock "Ulockfile"
fi

# Locks have been taken, so we're doing a build and we're committed to
# the directories we may have created so far.
newdirlist=

#
# Create mail_msg_file
#
mail_msg_file="${TMPDIR}/mail_msg"
touch $mail_msg_file
build_time_file="${TMPDIR}/build_time"
#
#	Move old LOGFILE aside
#	ATLOG directory already made by 'create_lock' above
#
if [ -f $LOGFILE ]; then
	mv -f $LOGFILE ${LOGFILE}-
fi
#
#	Build OsNet source
#
START_DATE=`date`
SECONDS=0
echo "\n==== Nightly $maketype build started:   $START_DATE ====" \
    | tee -a $LOGFILE > $build_time_file

# make sure we log only to the nightly build file
build_noise_file="${TMPDIR}/build_noise"
exec </dev/null >$build_noise_file 2>&1

echo "\n==== list of environment variables ====\n" >> $LOGFILE
env >> $LOGFILE

echo "\n==== Nightly argument issues ====\n" | tee -a $mail_msg_file >> $LOGFILE

if [ "$P_FLAG" = "y" ]; then
	obsolete_build GPROF | tee -a $mail_msg_file >> $LOGFILE
fi

if [ "$T_FLAG" = "y" ]; then
	obsolete_build TRACE | tee -a $mail_msg_file >> $LOGFILE
fi

if [ "$SE_FLAG" = "y" -o "$SD_FLAG" = "y" -o "$SH_FLAG" = "y" ]; then
	if [ "$i_FLAG" = "y" -o "$i_CMD_LINE_FLAG" = "y" ]; then
		echo "WARNING: the -S flags do not support incremental" \
		    "builds; forcing clobber\n" | tee -a $mail_msg_file >> $LOGFILE
		i_FLAG=n
		i_CMD_LINE_FLAG=n
	fi
	if [ "$N_FLAG" = "n" ]; then
		echo "WARNING: the -S flags do not support protocmp;" \
		    "protocmp disabled\n" | \
		    tee -a $mail_msg_file >> $LOGFILE
		N_FLAG=y
	fi
	if [ "$l_FLAG" = "y" ]; then
		echo "WARNING: the -S flags do not support lint;" \
		    "lint disabled\n" | tee -a $mail_msg_file >> $LOGFILE
		l_FLAG=n
	fi
	if [ "$C_FLAG" = "y" ]; then
		echo "WARNING: the -S flags do not support cstyle;" \
		    "cstyle check disabled\n" | tee -a $mail_msg_file >> $LOGFILE
		C_FLAG=n
	fi
else
	if [ "$N_FLAG" = "y" ]; then
		if [ "$p_FLAG" = "y" ]; then
			cat <<EOF | tee -a $mail_msg_file >> $LOGFILE
WARNING: the p option (create packages) is set, but so is the N option (do
         not run protocmp); this is dangerous; you should unset the N option
EOF
		else
			cat <<EOF | tee -a $mail_msg_file >> $LOGFILE
Warning: the N option (do not run protocmp) is set; it probably shouldn't be
EOF
		fi
		echo "" | tee -a $mail_msg_file >> $LOGFILE
	fi
fi

if [ "$a_FLAG" = "y" -a "$D_FLAG" = "n" -a "$F_FLAG" = "y" ]; then
	echo "WARNING: Neither DEBUG nor non-DEBUG build requested, but the" \
	    "'a' option was set." | tee -a $mail_msg_file >> $LOGFILE
fi

if [ "$D_FLAG" = "n" -a "$l_FLAG" = "y" ]; then
	echo "WARNING: DEBUG build not requested, but lint will be with" \
	    "DEBUG enabled.\n" \
	    | tee -a $mail_msg_file >> $LOGFILE
fi

if [ "$f_FLAG" = "y" ]; then
	if [ "$i_FLAG" = "y" ]; then
		echo "WARNING: the -f flag cannot be used during incremental" \
		    "builds; ignoring -f\n" | tee -a $mail_msg_file >> $LOGFILE
		f_FLAG=n
	fi
	if [ "$p_FLAG" != "y" -o "$l_FLAG" != "y" ]; then
		echo "WARNING: the -f flag requires -l and -p; ignoring -f\n" | \
		    tee -a $mail_msg_file >> $LOGFILE
		f_FLAG=n
	fi
fi

if [ "$w_FLAG" = "y" -a ! -d $ROOT ]; then
	echo "WARNING: -w specified, but no pre-existing proto area found;" \
	    "ignoring -w\n" | tee -a $mail_msg_file >> $LOGFILE
	w_FLAG=n
fi

if [ "$t_FLAG" = "n" ]; then
	#
	# We're not doing a tools build, so make sure elfsign(1) is
	# new enough to safely sign non-crypto binaries.  We test
	# debugging output from elfsign to detect the old version.
	#
	newelfsigntest=`SUNW_CRYPTO_DEBUG=stderr /usr/bin/elfsign verify \
	    -e /usr/lib/security/pkcs11_softtoken.so.1 2>&1 \
	    | egrep algorithmOID`
	if [ -z "$newelfsigntest" ]; then
		echo "WARNING: /usr/bin/elfsign out of date;" \
		    "will only sign crypto modules\n" | \
		    tee -a $mail_msg_file >> $LOGFILE
		export ELFSIGN_OBJECT=true
	elif [ "$VERIFY_ELFSIGN" = "y" ]; then
		echo "WARNING: VERIFY_ELFSIGN=y requires" \
		    "the -t flag; ignoring VERIFY_ELFSIGN\n" | \
		    tee -a $mail_msg_file >> $LOGFILE
	fi
fi

echo "==== Build environment ====\n" | tee -a $mail_msg_file >> $LOGFILE

# System
whence uname | tee -a $mail_msg_file >> $LOGFILE
uname -a 2>&1 | tee -a $mail_msg_file >> $LOGFILE
echo | tee -a $mail_msg_file >> $LOGFILE

# nightly (will fail in year 2100 due to SCCS flaw)
echo "$0 $@" | tee -a $mail_msg_file >> $LOGFILE
echo "%M% version %I% 20%E%\n" | tee -a $mail_msg_file >> $LOGFILE

# make
whence $MAKE | tee -a $mail_msg_file >> $LOGFILE
$MAKE -v | tee -a $mail_msg_file >> $LOGFILE
echo "number of concurrent jobs = $DMAKE_MAX_JOBS" |
    tee -a $mail_msg_file >> $LOGFILE

#
# Report the compiler versions.
#
if [ -f $SRC/Makefile ]; then
	srcroot=$SRC
elif [ -f $BRINGOVER_WS/usr/src/Makefile ]; then
	srcroot=$BRINGOVER_WS/usr/src
else
	echo "\nUnable to find \"Makefile\" in $BRINGOVER_WS/usr/src or $SRC." |
	    tee -a $mail_msg_file >> $LOGFILE
	exit 1
fi

( cd $srcroot
  for target in cc-version cc64-version java-version; do
	echo
	#
	# Put statefile somewhere we know we can write to rather than trip
	# over a read-only $srcroot.
	#
	rm -f $TMPDIR/make-state
	export SRC=$srcroot
	if $MAKE -K $TMPDIR/make-state -e $target 2>/dev/null; then
		continue
	fi
	touch $TMPDIR/nocompiler
  done
  echo
) | tee -a $mail_msg_file >> $LOGFILE

if [ -f $TMPDIR/nocompiler ]; then
	rm -f $TMPDIR/nocompiler
	build_ok=n
	echo "Aborting due to missing compiler." |
		tee -a $mail_msg_file >> $LOGFILE
	exit 1
fi

# as
whence as | tee -a $mail_msg_file >> $LOGFILE
as -V 2>&1 | head -1 | tee -a $mail_msg_file >> $LOGFILE
echo | tee -a $mail_msg_file >> $LOGFILE

# Check that we're running a capable link-editor
whence ld | tee -a $mail_msg_file >> $LOGFILE
LDVER=`ld -V 2>&1`
echo $LDVER | tee -a $mail_msg_file >> $LOGFILE
LDVER=`echo $LDVER | sed -e "s/.*-1\.//" -e "s/:.*//"`
if [ `expr $LDVER \< 422` -eq 1 ]; then
	echo "The link-editor needs to be at version 422 or higher to build" | \
	    tee -a $mail_msg_file >> $LOGFILE
	echo "the latest stuff, hope your build works." | \
	    tee -a $mail_msg_file >> $LOGFILE
fi

echo "\nBuild project:  $build_project\nBuild taskid:   $build_taskid" | \
    tee -a $mail_msg_file >> $LOGFILE

echo "\n==== Build version ====\n" | tee -a $mail_msg_file >> $LOGFILE
echo $VERSION | tee -a $mail_msg_file >> $LOGFILE

# Save the current proto area if we're comparing against the last build
if [ "$w_FLAG" = "y" -a -d "$ROOT" ]; then
    if [ -d "$ROOT.prev" ]; then
	rm -rf $ROOT.prev
    fi
    mv $ROOT $ROOT.prev
fi

#
#	Decide whether to clobber
#
if [ "$i_FLAG" = "n" -a -d "$SRC" ]; then
	echo "\n==== Make clobber at `date` ====\n" >> $LOGFILE

	cd $SRC
	# remove old clobber file
	rm -f $SRC/clobber.out
	rm -f $SRC/clobber-${MACH}.out

	# Remove all .make.state* files, just in case we are restarting
	# the build after having interrupted a previous 'make clobber'.
	find . \( -name SCCS -o -name 'interfaces.*' \) -prune \
	    -o -name '.make.*' -print | xargs rm -f

	$MAKE -ek clobber 2>&1 | tee -a $SRC/clobber-${MACH}.out >> $LOGFILE
	echo "\n==== Make clobber ERRORS ====\n" >> $mail_msg_file
	grep "$MAKE:" $SRC/clobber-${MACH}.out |
		egrep -v "Ignoring unknown host" \
		>> $mail_msg_file

	if [ "$t_FLAG" = "y" ]; then
		echo "\n==== Make tools clobber at `date` ====\n" >> $LOGFILE
		cd ${TOOLS}
		rm -f ${TOOLS}/clobber-${MACH}.out
		$MAKE -ek clobber 2>&1 | \
			tee -a ${TOOLS}/clobber-${MACH}.out >> $LOGFILE
		echo "\n==== Make tools clobber ERRORS ====\n" \
			>> $mail_msg_file
		grep "$MAKE:" ${TOOLS}/clobber-${MACH}.out \
			>> $mail_msg_file
		rm -rf ${TOOLS_PROTO}
		mkdir -p ${TOOLS_PROTO}
	fi

	rm -rf $ROOT

	# Get back to a clean workspace as much as possible to catch
	# problems that only occur on fresh workspaces.
	# Remove all .make.state* files, libraries, and .o's that may
	# have been omitted from clobber.  A couple of libraries are
	# under SCCS, so leave them alone.
	# We should probably blow away temporary directories too.
	cd $SRC
	find $relsrcdirs \( -name SCCS -o -name 'interfaces.*' \) -prune -o \
	    \( -name '.make.*' -o -name 'lib*.a' -o -name 'lib*.so*' -o \
	       -name '*.o' \) -print | \
	    grep -v 'tools/ctf/dwarf/.*/libdwarf' | xargs rm -f
else
	echo "\n==== No clobber at `date` ====\n" >> $LOGFILE
fi

#
#	Decide whether to bringover to the codemgr workspace
#
if [ "$n_FLAG" = "n" ]; then
	echo "\n==== bringover to $CODEMGR_WS at `date` ====\n" >> $LOGFILE
	# sleep on the parent workspace's lock
	while egrep -s write $BRINGOVER_WS/Codemgr_wsdata/locks
	do
		sleep 120
	done

	echo "\n==== BRINGOVER LOG ====\n" >> $mail_msg_file

	(staffer $TEAMWARE/bin/bringover -c "nightly update" -p $BRINGOVER_WS \
	    -w $CODEMGR_WS $BRINGOVER_FILES < /dev/null 2>&1 ||
		touch $TMPDIR/bringover_failed

         staffer bringovercheck $CODEMGR_WS >$TMPDIR/bringovercheck.out 2>&1

	 if [ -s $TMPDIR/bringovercheck.out ]; then
		echo "\n==== POST-BRINGOVER CLEANUP NOISE ====\n"
		cat $TMPDIR/bringovercheck.out
	 fi

	) | tee -a  $mail_msg_file >> $LOGFILE

	if [ -f $TMPDIR/bringover_failed ]; then
		rm -f $TMPDIR/bringover_failed
		build_ok=n
		echo "trouble with bringover, quitting at `date`." |
			tee -a $mail_msg_file >> $LOGFILE
		exit 1
	fi

	#
	# Possible transition from pre-split workspace to split
	# workspace.  See if the bringover changed anything.
	#
	CLOSED_IS_PRESENT="$orig_closed_is_present"
	check_closed_tree
else
	echo "\n==== No bringover to $CODEMGR_WS ====\n" >> $LOGFILE
fi

#
# Build tools if requested
#
if [ "$t_FLAG" = "y" ]; then
	export INTERNAL_RELEASE_BUILD ; INTERNAL_RELEASE_BUILD=
	export RELEASE_BUILD ; RELEASE_BUILD=
	unset EXTRA_OPTIONS
	unset EXTRA_CFLAGS

	export ONBLD_TOOLS=${ONBLD_TOOLS:=${TOOLS_PROTO}/opt/onbld}
	build_tools ${TOOLS_PROTO}
fi

#
# copy ihv proto area in addition to the build itself
#
if [ "$X_FLAG" = "y" ]; then
	copy_ihv_proto
fi

if [ "$i_FLAG" = "y" -a "$SH_FLAG" = "y" ]; then
	echo "\n==== NOT Building base OS-Net source ====\n" | \
	    tee -a $LOGFILE >> $mail_msg_file
else
	normal_build
fi

ORIG_SRC=$SRC
BINARCHIVE=${CODEMGR_WS}/bin-${MACH}.cpio.Z

if [ "$SE_FLAG" = "y" -o "$SD_FLAG" = "y" -o "$SH_FLAG" = "y" ]; then
	save_binaries

	echo "\n==== Retrieving SCCS files at `date` ====\n" >> $LOGFILE
	SCCSHELPER=${TMPDIR}/sccs-helper
	rm -f ${SCCSHELPER}
cat >${SCCSHELPER} <<EOF
#!/bin/ksh
cd \$1
cd ..
sccs get SCCS >/dev/null 2>&1
EOF
	cd $SRC
	chmod +x ${SCCSHELPER}
	find $relsrcdirs -name SCCS | xargs -L 1 ${SCCSHELPER}
	rm -f ${SCCSHELPER}
fi

if [ "$SD_FLAG" = "y" ]; then
	clone_source ${CODEMGR_WS} ${CRYPT_SRC} CRYPT_SRC
fi

# EXPORT_SRC comes after CRYPT_SRC since a domestic build will need
# $SRC pointing to the export_source usr/src.
if [ "$SE_FLAG" = "y" -o "$SD_FLAG" = "y" -o "$SH_FLAG" = "y" ]; then
	clone_source ${CODEMGR_WS} ${EXPORT_SRC} EXPORT_SRC
fi

if [ "$SD_FLAG" = "y" ]; then
	# drop the crypt files in place.
	cd ${EXPORT_SRC}
	echo "\nextracting crypt_files.cpio.Z onto export_source.\n" \
	    >> ${LOGFILE}
	zcat ${CODEMGR_WS}/crypt_files.cpio.Z | \
	    cpio -idmucvB 2>/dev/null >> ${LOGFILE}
	if [ "$?" = "0" ]; then
		echo "\n==== DOMESTIC extraction succeeded ====\n" \
		    >> $mail_msg_file
	else
		echo "\n==== DOMESTIC extraction failed ====\n" \
		    >> $mail_msg_file
	fi

fi

if [ "$SE_FLAG" = "y" -o "$SD_FLAG" = "y" -o "$SH_FLAG" = "y" ]; then
	# remove proto area here, since we don't clobber
	rm -rf "$ROOT"
	if [ "$t_FLAG" = "y" ]; then
		export INTERNAL_RELEASE_BUILD ; INTERNAL_RELEASE_BUILD=
		export RELEASE_BUILD ; RELEASE_BUILD=
		unset EXTRA_OPTIONS
		unset EXTRA_CFLAGS
		ORIG_TOOLS=$TOOLS
		TOOLS=${EXPORT_SRC}/usr/src/tools
		build_tools ${EXPORT_SRC}/usr/src/tools/proto
		TOOLS=$ORIG_TOOLS
	fi

	export EXPORT_RELEASE_BUILD ; EXPORT_RELEASE_BUILD=#
	normal_build
fi

if [ "$build_ok" = "y" ]; then
	echo "\n==== Creating protolist system file at `date` ====" \
		>> $LOGFILE
	protolist $ROOT > $ATLOG/proto_list_${MACH}
	echo "==== protolist system file created at `date` ====\n" \
		>> $LOGFILE

	if [ "$N_FLAG" != "y" ]; then
		echo "\n==== Impact on packages ====\n" >> $mail_msg_file

		# If there is a reference proto list, compare the build's proto
		# list with the reference to see changes in proto areas.
		# Use the current exception list.
		exc=etc/exception_list_$MACH
		if [ -f $SRC/pkgdefs/$exc ]; then
			ELIST="-e $SRC/pkgdefs/$exc"
		fi
		if [ "$X_FLAG" = "y" -a -f $IA32_IHV_WS/usr/src/pkgdefs/$exc ]; then
			ELIST="$ELIST -e $IA32_IHV_WS/usr/src/pkgdefs/$exc"
		fi

		if [ -f "$REF_PROTO_LIST" ]; then
			$PROTOCMPTERSE \
			  "Files in yesterday's proto area, but not today's:" \
			  "Files in today's proto area, but not yesterday's:" \
			  "Files that changed between yesterday and today:" \
			  ${ELIST} \
			  -d $REF_PROTO_LIST \
			  $ATLOG/proto_list_${MACH} \
				>> $mail_msg_file
		fi
		# Compare the build's proto list with current package
		# definitions to audit the quality of package definitions
		# and makefile install targets. Use the current exception list.
		PKGDEFS_LIST=""
		for d in $abssrcdirs; do
			if [ -d $d/pkgdefs ]; then
				PKGDEFS_LIST="$PKGDEFS_LIST -d $d/pkgdefs"
			fi
		done
		if [ "$X_FLAG" = "y" -a -d $IA32_IHV_WS/usr/src/pkgdefs ]; then
			PKGDEFS_LIST="$PKGDEFS_LIST -d $IA32_IHV_WS/usr/src/pkgdefs"
		fi

		$PROTOCMPTERSE \
		    "Files missing from the proto area:" \
		    "Files missing from packages:" \
		    "Inconsistencies between pkgdefs and proto area:" \
		    ${ELIST} \
		    ${PKGDEFS_LIST} \
		    $ATLOG/proto_list_${MACH} \
		    >> $mail_msg_file
	fi
fi

if [ "$u_FLAG" = "y"  -a "$build_ok" = "y" ]; then
	staffer cp $ATLOG/proto_list_${MACH} \
		$PARENT_WS/usr/src/proto_list_${MACH}
fi

# Update parent proto area if necessary. This is done now
# so that the proto area has either DEBUG or non-DEBUG kernels.
# Note that this clears out the lock file, so we can dispense with
# the variable now.
if [ "$U_FLAG" = "y" -a "$build_ok" = "y" ]; then
	echo "\n==== Copying proto area to $NIGHTLY_PARENT_ROOT ====\n" | \
	    tee -a $LOGFILE >> $mail_msg_file
	# The rm -rf command below produces predictable errors if
	# nightly is invoked from the parent's $ROOT/opt/onbld/bin,
	# and that directory is accessed via NFS.  This is because
	# deleted-but-still-open files don't actually disappear as
	# expected, but rather turn into .nfsXXXX junk files, leaving
	# the directory non-empty.  Since this is a not-unusual usage
	# pattern, and we still want to catch other errors here, we
	# take the unusal step of moving aside 'nightly' from that
	# directory (if we're using it).
	mypath=${0##*/root_$MACH/}
	if [ "$mypath" = $0 ]; then
		mypath=opt/onbld/bin/${0##*/}
	fi
	if [ $0 -ef $PARENT_WS/proto/root_$MACH/$mypath ]; then
		mv -f $0 $PARENT_WS/proto/root_$MACH
	fi
	rm -rf $PARENT_WS/proto/root_$MACH/*
	unset Ulockfile
	mkdir -p $NIGHTLY_PARENT_ROOT
	cd $ROOT
	( tar cf - . | ( cd $NIGHTLY_PARENT_ROOT;  umask 0; tar xpf - ) ) 2>&1 |
		tee -a $mail_msg_file >> $LOGFILE
fi

#
# do shared library interface verification
#

if [ "$A_FLAG" = "y" -a "$build_ok" = "y" ]; then
	echo "\n==== Check versioning and ABI information ====\n"  | \
	    tee -a $LOGFILE >> $mail_msg_file

	rm -rf $SRC/interfaces.ref
	if [ -d $SRC/interfaces.out ]; then
		mv $SRC/interfaces.out $SRC/interfaces.ref
	fi
	rm -rf $SRC/interfaces.out
	mkdir -p $SRC/interfaces.out

	intf_check -V -m -o -b $SRC/tools/abi/etc \
		-d $SRC/interfaces.out $ROOT 2>&1 | sort \
		> $SRC/interfaces.out/log

	# report any ERROR found in log file
	fgrep 'ERROR' $SRC/interfaces.out/log | sed 's/^ERROR: //' | \
		tee -a $LOGFILE >> $mail_msg_file

	if [ ! -d $SRC/interfaces.ref ] ; then
		mkdir -p $SRC/interfaces.ref
		if [ -d  $SRC/interfaces.out ]; then
			cp -r $SRC/interfaces.out/* $SRC/interfaces.ref
		fi
	fi

	echo "\n==== Diff versioning warnings (since last build) ====\n" | \
	    tee -a $LOGFILE >> $mail_msg_file

	out_vers=`grep ^VERSION $SRC/interfaces.out/log`;
	ref_vers=`grep ^VERSION $SRC/interfaces.ref/log`;

	# Report any differences in WARNING messages between last
	# and current build.
	if [ "$out_vers" = "$ref_vers" ]; then
		diff $SRC/interfaces.ref/log $SRC/interfaces.out/log | \
		    fgrep 'WARNING' | sed 's/WARNING: //' | \
		    tee -a $LOGFILE >> $mail_msg_file
	fi
fi

if [ "$r_FLAG" = "y" -a "$build_ok" = "y" ]; then
	echo "\n==== Check ELF runtime attributes ====\n" | \
	    tee -a $LOGFILE >> $mail_msg_file

	LDDUSAGE="^ldd: does not support -e"
	LDDWRONG="wrong class"
	CRLERROR="^crle:"
	CRLECONF="^crle: configuration file:"

	rm -f $SRC/runtime.ref
	if [ -f $SRC/runtime.out ]; then
		egrep -v "$LDDUSAGE|$LDDWRONG|$CRLERROR|$CRLECONF" \
			$SRC/runtime.out > $SRC/runtime.ref
	fi

	# If we're doing a debug build the proto area will be left with
	# debuggable objects, thus don't assert -s.
	if [ "$D_FLAG" = "y" ]; then
		rtime_sflag=""
	else
		rtime_sflag="-s"
	fi
	check_rtime -d $ROOT -i -m -o $rtime_sflag $ROOT 2>&1 | \
	    egrep -v ": unreferenced object=$ROOT/.*/lib(w|intl|thread|pthread).so" | \
	    egrep -v ": unused object=$ROOT/.*/lib(w|intl|thread|pthread).so" | \
	    sort >$SRC/runtime.out

	# Determine any processing errors that will affect the final output
	# and display these first.
	grep -l "$LDDUSAGE" $SRC/runtime.out > /dev/null
	if [ $? -eq 0 ]; then
	    echo "WARNING: ldd(1) does not support -e.  The version of ldd(1)" | \
		tee -a $LOGFILE >> $mail_msg_file
	    echo "on your system is old - 4390308 (s81_30) is required.\n" | \
		tee -a $LOGFILE >> $mail_msg_file
	fi
	grep -l "$LDDWRONG" $SRC/runtime.out > /dev/null
	if [ $? -eq 0 ]; then
	    echo "WARNING: wrong class message detected.  ldd(1) was unable" | \
		tee -a $LOGFILE >> $mail_msg_file
	    echo "to execute an object, thus it could not be checked fully." | \
		tee -a $LOGFILE >> $mail_msg_file
	    echo "Perhaps a 64-bit object was encountered on a 32-bit system," | \
		tee -a $LOGFILE >> $mail_msg_file
	    echo "or an i386 object was encountered on a sparc system?\n" | \
		tee -a $LOGFILE >> $mail_msg_file
	fi
	grep -l "$CRLECONF" $SRC/runtime.out > /dev/null
	if [ $? -eq 0 ]; then
	    echo "WARNING: creation of an alternative dependency cache failed." | \
		tee -a $LOGFILE >> $mail_msg_file
	    echo "Dependencies will bind to the base system libraries.\n" | \
		tee -a $LOGFILE >> $mail_msg_file
	    grep "$CRLECONF" $SRC/runtime.out | \
		tee -a $LOGFILE >> $mail_msg_file
	    grep "$CRLERROR" $SRC/runtime.out | grep -v "$CRLECONF" | \
		tee -a $LOGFILE >> $mail_msg_file
	    echo "\n" | tee -a $LOGFILE >> $mail_msg_file
	fi

	egrep '<dependency no longer necessary>' $SRC/runtime.out | \
	    tee -a $LOGFILE >> $mail_msg_file

	# NEEDED= and RPATH= are informational; report anything else that we
	# haven't already.
	egrep -v "NEEDED=|RPATH=|$LDDUSAGE|$LDDWRONG|$CRLERROR|$CRLECONF" \
	    $SRC/runtime.out | tee -a $LOGFILE >> $mail_msg_file

	# probably should compare against a 'known ok runpaths' list
	if [ ! -f $SRC/runtime.ref ]; then
		egrep -v "$LDDUSAGE|$LDDWRONG|$CRLERROR|$CRLECONF" \
			$SRC/runtime.out >  $SRC/runtime.ref
	fi

	echo "\n==== Diff ELF runtime attributes (since last build) ====\n" \
	    >> $mail_msg_file

	egrep -v "$LDDUSAGE|$LDDWRONG|$CRLERROR|$CRLECONF" $SRC/runtime.out | \
	    diff $SRC/runtime.ref - >> $mail_msg_file
fi

# DEBUG lint of kernel begins

if [ "$i_CMD_LINE_FLAG" = "n" -a "$l_FLAG" = "y" ]; then
	if [ "$LINTDIRS" = "" ]; then
		# LINTDIRS="$SRC/uts y $SRC/stand y $SRC/psm y"
		LINTDIRS="$SRC y"
	fi
	set $LINTDIRS
	while [ $# -gt 0 ]; do
		dolint $1 $2; shift; shift
	done
else
	echo "\n==== No '$MAKE lint' ====\n" >> $LOGFILE
fi

# "make check" begins

if [ "$i_CMD_LINE_FLAG" = "n" -a "$C_FLAG" = "y" ]; then
	# remove old check.out
	rm -f $SRC/check.out

	rm -f $SRC/check-${MACH}.out
	cd $SRC
	$MAKE -ek check 2>&1 | tee -a $SRC/check-${MACH}.out >> $LOGFILE
	echo "\n==== cstyle/hdrchk errors ====\n" >> $mail_msg_file

	grep ":" $SRC/check-${MACH}.out |
		egrep -v "Ignoring unknown host" | \
		sort | uniq >> $mail_msg_file
else
	echo "\n==== No '$MAKE check' ====\n" >> $LOGFILE
fi

echo "\n==== Find core files ====\n" | \
    tee -a $LOGFILE >> $mail_msg_file

find $abssrcdirs -name core -a -type f -exec file {} \; | \
	tee -a $LOGFILE >> $mail_msg_file

if [ "$f_FLAG" = "y" -a "$build_ok" = "y" ]; then
	echo "\n==== Diff unreferenced files (since last build) ====\n" \
	    | tee -a $LOGFILE >>$mail_msg_file
	rm -f $SRC/unref-${MACH}.ref
	if [ -f $SRC/unref-${MACH}.out ]; then
		mv $SRC/unref-${MACH}.out $SRC/unref-${MACH}.ref
	fi

	findunref -t $SRC/.build.tstamp $SRC/.. \
	    ${TOOLS}/findunref/exception_list \
	    2>> $mail_msg_file | sort | \
	    sed -e s=^./src/=./= -e s=^./closed/=../closed/= \
	    > $SRC/unref-${MACH}.out

	if [ ! -f $SRC/unref-${MACH}.ref ]; then
		cp $SRC/unref-${MACH}.out $SRC/unref-${MACH}.ref
	fi

	diff $SRC/unref-${MACH}.ref $SRC/unref-${MACH}.out >>$mail_msg_file
fi

# Verify that the usual lists of files, such as exception lists,
# contain only valid references to files.  If the build has failed,
# then don't check the proto area.
CHECK_PATHS=${CHECK_PATHS:-y}
if [ "$CHECK_PATHS" = y -a "$N_FLAG" != y ]; then
	echo "\n==== Check lists of files ====\n" | tee -a $LOGFILE \
		>>$mail_msg_file
	arg=-b
	[ "$build_ok" = y ] && arg=
	checkpaths $arg $ROOT 2>&1 | tee -a $LOGFILE >>$mail_msg_file
fi

if [ "$M_FLAG" != "y" -a "$build_ok" = y ]; then
	echo "\n==== Impact on file permissions ====\n" \
		>> $mail_msg_file
	#
	# Get pkginfo files from usr/src/pkgdefs
	#
	pmodes -qvdP \
	`for d in $abssrcdirs; do
		if [ -d "$d/pkgdefs" ]
		then
			find $d/pkgdefs -name pkginfo.tmpl -print -o -name .del\* -prune
		fi
	 done | sed -e 's:/pkginfo.tmpl$::' | sort -u ` >> $mail_msg_file
fi

if [ "$w_FLAG" = "y" -a "$build_ok" = "y" ]; then
	echo "\n==== Objects that differ since last build ====\n" | \
	    tee -a $LOGFILE >> $mail_msg_file

	if [ "$t_FLAG" = "y" ]; then
	    wsdiff -t -r ${TMPDIR}/wsdiff.results $ROOT.prev $ROOT | \
		tee -a $LOGFILE >> $mail_msg_file
	else
	    wsdiff -r ${TMPDIR}/wsdiff.results $ROOT.prev $ROOT  | \
		tee -a $LOGFILE >> $mail_msg_file
	fi
fi

END_DATE=`date`
echo "==== Nightly $maketype build completed: $END_DATE ====" | \
    tee -a $LOGFILE >> $build_time_file

typeset -Z2 minutes
typeset -Z2 seconds

elapsed_time=$SECONDS
((hours = elapsed_time / 3600 ))
((minutes = elapsed_time / 60  % 60))
((seconds = elapsed_time % 60))

echo "\n==== Total build time ====" | \
    tee -a $LOGFILE >> $build_time_file
echo "\nreal    ${hours}:${minutes}:${seconds}" | \
    tee -a $LOGFILE >> $build_time_file

if [ "$u_FLAG" = "y" -a "$f_FLAG" = "y" -a "$build_ok" = "y" ]; then
	staffer cp ${SRC}/unref-${MACH}.out $PARENT_WS/usr/src/

	#
	# Produce a master list of unreferenced files -- ideally, we'd
	# generate the master just once after all of the nightlies
	# have finished, but there's no simple way to know when that
	# will be.  Instead, we assume that we're the last nightly to
	# finish and merge all of the unref-${MACH}.out files in
	# $PARENT_WS/usr/src/.  If we are in fact the final ${MACH} to
	# finish, then this file will be the authoritative master
	# list.  Otherwise, another ${MACH}'s nightly will eventually
	# overwrite ours with its own master, but in the meantime our
	# temporary "master" will be no worse than any older master
	# which was already on the parent.
	#

	set -- $PARENT_WS/usr/src/unref-*.out
	cp "$1" ${TMPDIR}/unref.merge
	shift

	for unreffile; do
		comm -12 ${TMPDIR}/unref.merge "$unreffile" > ${TMPDIR}/unref.$$
		mv ${TMPDIR}/unref.$$ ${TMPDIR}/unref.merge
	done

	staffer cp ${TMPDIR}/unref.merge $PARENT_WS/usr/src/unrefmaster.out
fi

#
# All done save for the sweeping up.
# (whichever exit we hit here will trigger the "cleanup" trap which
# optionally sends mail on completion).
#
if [ "$build_ok" = "y" ]; then
	exit 0
fi
exit 1
