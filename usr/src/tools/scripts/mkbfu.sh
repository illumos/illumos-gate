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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# 
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Make archives suitable for bfu

#
# The CDPATH variable causes ksh's `cd' builtin to emit messages to stdout
# under certain circumstances, which can really screw things up; unset it.
#
unset CDPATH

fail() {
	echo $* >&2
	exit 1
}

# Place a limit on the number of background jobs we can produce at one
# time.  The mechanism used is crude; we wait for all jobs to complete
# before continuing.  It'd be nice if ksh actually had such a native
# facility.
bgcheck() {
	bgctr=$((bgctr + 1))
	if [ $bgctr -ge $bgmax ]; then
	        wait
	        bgctr=0
		for outf in $CPIODIR/*.out; do
			errf=${outf%.out}.err
			if [ -s $errf ]; then
				echo "Failed to create\c" >&2
				cat $outf $errf >&2
			else
				echo "Creating\c"
				cat $outf
			fi
			rm -f $outf $errf
		done
	fi
}
bgctr=0
bgmax=${DMAKE_MAX_JOBS:-1}

# Produce a named archive.  Archives always have two names -- the
# first part is an identifier for the archive, the second part is
# 'root' or 'usr' or 'lib' or 'sbin' or 'kernel'.
create_archive() {
	arc="$CPIODIR/$1.$2"
	outf="${arc}.out"
	cpioerr="${arc}.cpioerr"
	echo " $1 $2 archive:\t\c" >$outf
	eval $cpio >$arc$ext
	awk '/^[0-9]* blocks$/ { blocks=1; print $0; next }
	{ print $0 > "/dev/stderr" }
	END {
		if (!blocks) {
			# Terminate the "echo \c" line above.
			print
			print "No cpio block count" > "/dev/stderr"
		}
	}' <$cpioerr >>$outf
	rm -f $cpioerr
}

ext=
filter=
compressor=
usage="Usage: $0 [-f filter] [-z] proto-dir archive-dir"
prove_you_mean_it="\n\
\n\
Unless invoked directly by makebfu, this script will produce archives with\n\
incorrect permissions which will brickify a system if installed.  You most\n\
likely wanted to run makebfu instead; if not, set\n\n\
\t\tI_REALLY_WANT_TO_RUN_MKBFU=YES\n\n\
in your environment and try again.\n\n\n"

[ -n "$I_REALLY_WANT_TO_RUN_MKBFU" ] || fail "$prove_you_mean_it"
[ "$I_REALLY_WANT_TO_RUN_MKBFU" = "YES" ] || fail "$prove_you_mean_it"

while getopts :f:z opt
do
	case "$opt" in
	    f)	filter="$OPTARG";;
	    z)	compressor="gzip -c"
		ext=".gz";;
	    *)	fail "$usage";;
	esac
done
shift $(($OPTIND - 1))

[ $# -eq 2 ] || fail "$usage"

# The extra subshell allows us to wait for cpio to exit completely (rather
# that merely closing stdout) before attempting to examine the stderr output
# file.  Otherwise, we'll race with cpio's completion.
cpio='( ( cpio -ocB 2>$cpioerr ); true )'
if [ "$filter" ]; then
	cpio="$cpio | $filter"
fi
if [ "$compressor" ]; then
	cpio="$cpio | $compressor"
fi

PROTO=$1
CPIODIR=$2

CLASS=`uname -m`

[ -d $PROTO ] || fail "Proto directory $PROTO does not exist."

cd $PROTO

rm -rf $CPIODIR
mkdir -p $CPIODIR

# Create "new style" archives if Zones are present, with lib, sbin and kernel
# in their own archives; otherwise create "old style" archives with everything
# in generic.root
if [ -d etc/zones ]; then
	( {	FILELIST=`ls . | grep -v usr | grep -v platform |
			grep -v kernel | grep -v boot | grep -v sbin |
			grep -v lib | sed -e "s@^@./@"`
		find $FILELIST -depth -print
		echo "./usr"
		echo "./platform"
		echo "./lib"
		echo "./sbin"
		echo "./kernel"
	} | create_archive generic root ) 2>$CPIODIR/generic.root.err &
	bgcheck

	( {	FILELIST=`ls ./lib | sed -e "s@^@./lib/@"`
		find $FILELIST -depth -print
	} | create_archive generic lib ) 2>$CPIODIR/generic.lib.err &
	bgcheck

	( {	FILELIST=`ls ./sbin | sed -e "s@^@./sbin/@"`
		find $FILELIST -depth -print
	} | create_archive generic sbin ) 2>$CPIODIR/generic.sbin.err &
	bgcheck

	( {	FILELIST=`ls ./kernel | sed -e "s@^@./kernel/@"`
		find $FILELIST -depth -print
	} | create_archive generic kernel ) 2>$CPIODIR/generic.kernel.err &
	bgcheck
else
	( {     FILELIST=`ls . | grep -v usr | grep -v platform |
			grep -v boot | sed -e "s@^@./@"`
		find $FILELIST -depth -print
		echo "./usr"
		echo "./platform"
	} | create_archive generic root ) 2>$CPIODIR/generic.root.err &
	bgcheck
fi

( {	FILELIST=`ls ./usr | grep -v platform | sed -e "s@^@./usr/@"`
	find $FILELIST -depth -print | egrep -v -e "./usr/share/src"
	echo "./usr/platform"
} | create_archive generic usr ) 2>$CPIODIR/generic.usr.err &
bgcheck

for i in `cd platform; find * -prune \( -type d -o -type l \) -print`
do
	( {	FILELIST=`ls -1 ./platform | grep "$i$" |
		    sed -e "s@^@./platform/@"`
		find $FILELIST -depth -print
	} | create_archive $i root ) 2>$CPIODIR/${i}.root.err &
	bgcheck

	( {	FILELIST=`ls -1 ./usr/platform | grep "$i$" |
		    sed -e "s@^@./usr/platform/@"`
		find $FILELIST -depth -print
	} | create_archive $i usr ) 2>$CPIODIR/${i}.usr.err &
	bgcheck
done

if [ -d boot ]; then
	if [ "$CLASS" = "i86pc" ]; then
		ARCHIVECLASS="$CLASS"
	else
		ARCHIVECLASS="generic"
	fi
	( find boot -depth -print | create_archive $ARCHIVECLASS boot ) \
	    2>$CPIODIR/$ARCHIVECLASS.boot.err &
	bgcheck
fi

# If there are any background jobs left, then gather them now.
if [ $bgctr -gt 0 ]; then
	bgmax=0
	bgcheck
fi
