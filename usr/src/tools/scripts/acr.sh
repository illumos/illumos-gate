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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"

#
# usage: acr [root [archivedir]]
#
# examples:  acr
#	     acr /export/home/zone/root
#	     acr /export/home/zone/root ${CODEMGR_WS}/archives/sparc/nightly
#

if [ $# -gt 2 ] ; then
	print -u2 "usage:  $0 <root> <archivedir>"
	exit 1
fi

root=${1-/}
archivedir=$2
if [ -z "$archivedir" -o "$archivedir" = again ]; then
	if [ ! -s $root/etc/motd ]; then
		print -u2 "$root/etc/motd not found; this doesn't look like a" \
		    "valid root."
		exit 1
	fi
	archivedir=$(nawk '/^bfu.ed from / { print $3; exit }' $root/etc/motd)
fi

if [ ! -d "$archivedir" ]; then
    	print -u2 "Archive directory '$archivedir' not found."
	exit 1
fi

#
# temporary file scorecard:
#
# conflictscripts	list of scripts we need to run.
#
# installnew		list of editable files without class action scripts
#
# processedscript	basename of class action script edited to NOP
#			installf/removef's and use /tmp/bfubin
#
# allresults		log of all class action script output.
#
# thisresult		log of most recent class action script
#

tmpdir=$(mktemp -t -d acr.XXXXXX)

if [ -z "$tmpdir" ] ; then
    	print -u2 "mktemp failed to produce output; aborting."
	exit 1
fi

if [ ! -d $tmpdir ] ; then
    	print -u2 "mktemp failed to create a directory; aborting."
	exit 1
fi

conflictscripts=$tmpdir/conflictscripts
installnew=$tmpdir/installnew
allresults=$tmpdir/allresults
thisresult=$tmpdir/thisresult
processedscript=$tmpdir/processedscript

#
# This file is left over (on purpose) by BFU so that in a post-BFU environment
# we know which zones BFU processed.
#
bfu_zone_list=$root/.bfu_zone_list

get_cr_archive() {
	compressed_archive=$archivedir/conflict_resolution.gz
	if [ ! -s $compressed_archive ] ; then
		print -u2 "Failed to find conflict resolution information" \
		    "at $compressed_archive."
		return 1
	fi

	print -n "Getting ACR information from $archivedir... "

	gzip -d -c $compressed_archive | \
	    (cd $tmpdir; cpio -idmucB > /dev/null 2>&1) || return 1

	crdir=$tmpdir/conflict_resolution

	if [ ! -d $crdir ] ; then
		print -u2 "The conflict resolution archive is missing the" \
		    "conflict_resolution directory."
		return 1
	fi

	if [ ! -f $crdir/editable_file_db ] ; then
		print -u2 "The conflict resolution archive is missing the" \
			"editable file list."
		return 1
	fi
	print "ok"
	return 0
}

#
# If we're running after a BFU, some behaviors are different.
#
if [ -d /tmp/bfubin ] ; then
	bfu_alt_reality="true"
else
	bfu_alt_reality="false"
fi


acr_a_root() {
	typeset root
	typeset zone

	root=$1
	zone=$2

	print "ZONE $2 on $1" >> $allresults


	rm -f $conflictscripts
	rm -f $installnew

	#
	# The files that need to be processed are those that were stored by
	# bfu in bfu.conflicts.  Just process those that changed in the
	# distribution since the last bfu (those that are listed in the
	# $root/bfu.conflicts/NEW file).
	#
	if [ ! -d $root/bfu.conflicts ] ; then
		print -u2 "No BFU conflict information."
		return 1
	fi

	if [ ! -s $root/bfu.conflicts/NEW ] ; then
		print "No conflicts to resolve."
		return 0
	fi

	#
	# Some class-action scripts rely on being run in the order defined in
	# packages.  The $crdir/editable_file_db file contains the classes
	# in the correct order, so we preserve that order.
	#
	cat $crdir/editable_file_db | \
	while read filename script pkg pkginst isa mach unique pkgdef
	do
		grep "^$filename\$" $root/bfu.conflicts/NEW >> /dev/null || \
		    continue

		if [ "$mach" != "-" -a  $(uname -m) != "$mach" ] ; then
			continue
		fi

		print $filename $script $pkg $pkginst $isa $mach $unique \
		    $pkgdef >> $conflictscripts
	done

	if [ ! -s $conflictscripts ] ; then
		print "\nNo upgrade scripts were found for any of the" \
		    "conflicting files."
		return 1
	fi


	#
	# Look for files that are in the conflict list, but don't have
	# entries in the $conflictscripts file.  These have no
	# install scripts, so should just be copied. (The fact that such
	# files exist indicates a bug in bfu or possibly in the Solaris
	# packaging.  If these are really editable files, they should have
	# class action scripts.  If not, bfu shouldn't special-case them.)
	#
	cat $root/bfu.conflicts/NEW | while read filename ; do
		grep "$filename " $conflictscripts >> /dev/null
		if [ $? != 0 ] ; then
			print $filename >> $installnew
		fi
	done

	if [ -s $installnew ] ; then
		print "\n    The following files did not have conflict" \
		    "resolution scripts; this may"
		print "    indicate a bug in BFU.  The new versions will be" \
		    "installed.  The previous"
		print "    versions of these files can be found in" \
		    "$root/bfu.child:\n"
		cat $installnew | sed 's/^/        /'
		print
	fi

	UPDATE=yes
	BASEDIR=$root
	PKGSAV=/tmp
	PKG_INSTALL_ROOT=$root
	export UPDATE BASEDIR PKGSAV PKG_INSTALL_ROOT

	column_fmt='    %-35s  %-20s '

	printf "\n$column_fmt %s\n" "FILE" "ACTION" "STATUS"
	cat $conflictscripts | while read filename script pkg pkginst isa mach \
	    unique pkgdef ; do
		if [ "$script" = "upgrade_default" ] ; then
			msg=`printf "$column_fmt" \
			    $filename "upgrade_default_copy"`
			cp $root/bfu.conflicts/$filename $root/$filename
			if [ $? != 0 ]; then
				printf "$msg ok\n"
				continue
			else
				printf "$msg FAIL\n" 1>&2
				return 1
			fi
		fi

		if [ "$unique" = "c" ] ; then
			scriptloc=$crdir/$pkgdef/$script
		else
			scriptloc=$crdir/$pkgdef/$pkginst/$script
		fi
		msg=`printf "$column_fmt" $filename $script`

		#
		# If we are running in the post-BFU alternate reality, we need
		# to modify the class action script to work in that alternate
		# reality.  Otherwise, we merely need to "neuter" installf
		# and removef.  In any event, skip this one and go to the next
		# if the sed fails.
		#
		if [ $bfu_alt_reality = "true" ] ; then
			sed -e 's,^#!/bin/sh,#!/tmp/bfubin/sh,' \
			    -e 's,/usr/bin/,/tmp/bfubin/,g' \
			    -e 's,/usr/bin:,/tmp/bfubin:,' \
			    -e 's,installf,/tmp/bfubin/true,' \
			    -e 's,removef,/tmp/bfubin/true,' \
			    $scriptloc > $processedscript.$script
			error=$?
		else
			sed -e 's,installf,/usr/bin/true,' \
			    -e 's,removef,/usr/bin/true,' \
			    $scriptloc > $processedscript.$script
			error=$?
		fi

		if [ $error != 0 ] ; then
			printf "$msg FAIL (sed surgery->$error)\n" 1>&2
			continue
		fi

		chmod +x $processedscript.$script
		error=$?
		if [ $error != 0 ] ; then
			printf "$msg FAIL (chmod->$error)\n" 1>&2
			continue
		fi

		PKG=$pkg
		PKGINST=$pkg
		if [ $mach = "-" ] ; then
			ARCH=$isa
		else
			ARCH=$isa.$mach
		fi
		export PKG PKGINST ARCH

		print "PROCESSING $filename with $script" >> $allresults
		print $root/bfu.conflicts/$filename $root/$filename |
			$processedscript.$script > $thisresult 2>&1
		error=$?
		if [ $error != 0 ] ; then
			printf "$msg FAIL (exit $error)\n" 1>&2
			print -u2 "    Output of upgrade script:"
			sed 's/^/        /' < $thisresult >&2
		else
			printf "$msg ok\n"
		fi
		cat $thisresult >> $allresults
		print "RETURN CODE: $error" >> $allresults
	done

	if [ -s $installnew ] ; then
		cat $installnew | while read filename ; do

			msg=`printf "$column_fmt" $filename \
			    "cp from new version"`
			cp $root/bfu.conflicts/$filename $root/$filename
			error=$?
			if [ $error != 0 ] ; then
				printf "$msg FAIL (exit $error)\n" 1>&2
			else
				printf "$msg ok\n"
			fi

		done
	fi
}

#
# If we're post-BFU, then BFU should have left us a file listing which zones it
# processed.  If we're not post-BFU, just process all installed native and
# Sn-1 zones.
#
if [ $bfu_alt_reality = "false" ]; then
	zoneadm list -pi | nawk -F: '{
		if ($3 == "installed" &&
		    ($6 == "native" || $6 == "" || $6 == "sn1")) {
			printf "%s %s\n", $2, $4
		}
	}' > $bfu_zone_list
fi

#
# To be terse, check whether there is any work to do at all; if not,
# just print one line and exit.
#
need_resolve=false
if [ -s $root/bfu.conflicts/NEW ]; then
	need_resolve=true
else
	if [ -s $bfu_zone_list ]; then
		cat $bfu_zone_list | while read zone zonepath; do
			if [ -s $zonepath/root/bfu.conflicts/NEW ] ; then
				need_resolve=true
			fi
		done
	fi
fi

if [ "$need_resolve" = "false" ]; then
	print "No conflicts to resolve."
	exit 0
fi

get_cr_archive || exit 1

printf "\nProcessing global zone:\t"
acr_a_root $root "global"

if [ $root != "/" ]; then
	printf "\nSkipping non-global zones (root is not /)"
else
	if [ -s $bfu_zone_list ]; then
		cat $bfu_zone_list | while read zone zonepath; do
			printf "\nProcessing zone $zone:\t"
			acr_a_root $zonepath/root $zone
		done
	fi
fi

echo

cr_args=${root:+ -R $root}
LD_LIBRARY_PATH=/tmp/bfulib PATH=/tmp/bfubin \
    /tmp/bfubin/ksh $root/boot/solaris/bin/create_ramdisk $cr_args

print "Finished.  See $allresults for complete log."
