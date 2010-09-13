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

#
# Because we build more than one copy of perl at the same time we need each
# to have its own copy of the contrib subdirectory so that the concurrent
# builds don't interfere with each other.  Rather than duplicating the contents
# of the contrib directory under each version of perl we copy the clearfiles
# from usr/src/cmd/perl/contrib to the appropriate build directory, taking
# care only to do the copy if necessary so as not to cause unnecessary rebuilds.
#

function usage
{
	printf 'copy_contrib: usage is <src dir> <dst dir> <module> ...\n'
	exit 1
}

# Check arguments.
typeset -r src=$1
typeset -r dst=$2
[[ $src = $dst || ! ( -d $src && -d $dst ) ]] && usage
shift 2
typeset -r modules=$*
[[ -z $modules ]] && usage
typeset -r pwd=$PWD

#
# Make sure all the modules have the necessary clearfiles fetched,
# but only if we have SCCS files (not true for the source product).
#
for dir in $(cd $src && find $modules -type d -name SCCS); do
	dir=${dir%/SCCS}
	cd $src/$dir
	for file in SCCS/s.*; do
		file=${file#SCCS/s\.}
		if [[ ! ( -f $file || -f SCCS/p.$file ) ]]; then
			set -e
			printf 'sccs get %s/%s\n' $dir $file 
			sccs get $file
			set +e
		fi
	done
	cd $pwd
done

#
# Now copy all the clearfiles over to the destination directory, but only if
# the destination file doesn't exist or is older than the source file.
# Note we also ignore the Teamware req.flg and inc.flg files, to prevent
# Teamware bringover and putback warning about them not being in SCCS.
#

for obj in $(cd $src && find $modules -name SCCS -prune -o -print); do
	# Handle directories.
	if [[ -d $src/$obj ]]; then
		# Create destination directory if required.
		if [[ ! -d $dst/$obj ]]; then
			set -e
			printf 'mkdir -p %s/%s\n' $dst $obj
			mkdir -p $dst/$obj
			set +e
		fi
		
	# Handle plain files.
	elif [[ -f $src/$obj ]]; then
		if [[ $obj != */@(req|inc).flg && \
		    $src/$obj -nt $dst/$obj ]]; then
			set -e
			rm -f $dst/$obj
			printf 'cp -p %s/%s %s/%s\n' $src $obj $dst $obj
			cp -p $src/$obj $dst/$obj
			set +e
		fi

	# Anything else isn't handled.
	else
		printf 'copy_contrib: ERROR: unable to copy %s/%s' $src $obj
		exit 1
	fi
done
exit 0
