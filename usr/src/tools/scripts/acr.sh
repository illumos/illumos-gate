#!/bin/ksh -p
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

if [ ! -d $root/bfu.conflicts ] ; then
	print -u2 "No BFU conflict information."
	exit 1
fi

if [ ! -s $root/bfu.conflicts/NEW ] ; then
	print "No conflicts to resolve."
	exit 0
fi

compressed_archive=$archivedir/conflict_resolution.gz
if [ ! -s $compressed_archive ] ; then
	print -u2 "There is no conflict resolution information in the archive."
	exit 1
fi

print -n "Getting conflict resolution information from $compressed_archive: "

gzip -d -c $compressed_archive | (cd $tmpdir; cpio -idmucB 2>&1) || exit 1

crdir=$tmpdir/conflict_resolution

if [ ! -d $crdir ] ; then
    	print -u2 "The conflict resolution archive is missing the conflict_resolution directory."
	exit 1
fi

if [ ! -f $crdir/editable_file_db ] ; then
    	print -u2 "The conflict resolution archive is missing the editable file list."
	exit 1
fi

#
# The files that need to be processed are those that were stored by
# bfu in bfu.conflicts.  Just process those that changed in the 
# distribution since the last bfu (those that are listed in the
# $root/bfu.conflicts/NEW file).
# 
print "Building command list for the class action scripts:"

#
# Some class-action scripts rely on being run in the order defined in
# packages.  The $crdir/editable_file_db
# file contains the classes in the correct order, so we preserve that order.
#
cat $crdir/editable_file_db | \
while read filename script pkg pkginst isa mach unique pkgdef
do
	grep "^$filename\$" $root/bfu.conflicts/NEW >> /dev/null || continue
	if [ "$mach" != "-" -a  $(uname -m) != "$mach" ] ; then
			continue
	fi
	print $filename $script $pkg $pkginst $isa $mach $unique $pkgdef \
	    >> $conflictscripts
done

if [ ! -s $conflictscripts ] ; then
	print "No upgrade scripts were found for any of the conflicting files."
	exit 1
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
	print "The following files did not have conflict resolution scripts."
	print "The new versions will be installed.  The previous versions of"
	print "these files can be found in $root/bfu.child if you want to"
	print "restore them."
	cat $installnew
fi

UPDATE=yes
BASEDIR=$root
PKGSAV=/tmp
PKG_INSTALL_ROOT=$root
export UPDATE BASEDIR PKGSAV PKG_INSTALL_ROOT

print "Begin processing files"

cat $conflictscripts | while read filename script pkg pkginst isa mach \
	unique pkgdef ; do
	print "PROCESSING $filename"
	if [ "$script" = "upgrade_default" ] ; then
		if cp $root/bfu.conflicts/$filename $root/$filename ; then
		    	continue
		else
		    	print -u2 "upgrade_default copy of $filename failed"
			exit 1
		fi
	fi

	if [ "$unique" = "c" ] ; then
		scriptloc=$crdir/$pkgdef/$script
	else
		scriptloc=$crdir/$pkgdef/$pkginst/$script
	fi
		
	#
	# If we are running in the post-BFU alternate reality, we need 
	# to modify the class action script to work in that alternate 
	# reality.  Otherwise, we merely need to "neuter" installf 
	# and removef.  In any event, skip this one and go to the next
	# if the sed fails.
	#

	if [ -d /tmp/bfubin ] ; then
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
	    	print -u2 "sed surgery on $scriptloc failed with" \
		    "error = $error"
		continue
	fi

	chmod +x $processedscript.$script
	error=$?
	if [ $error != 0 ] ; then
	    	print -u2 "chmod +x $processedscript.$script failed" \
		    "with error = $error"
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

	print "PROCESSING $filename" >> $allresults
	print $root/bfu.conflicts/$filename $root/$filename |
		$processedscript.$script > $thisresult 2>&1
	error=$?
	if [ $error != 0 ] ; then
		print -u2 "upgrade script for $file failed with error = $error"
		print -u2 "Output of upgrade script:"
		cat $thisresult >&2
	fi
	cat $thisresult >> $allresults
	print "RETURN CODE : $error" >> $allresults
done

if [ -s $installnew ] ; then
	cat $installnew | while read filename ; do
		cp $root/bfu.conflicts/$filename $root/$filename
	done
fi

print See $allresults for more information.
