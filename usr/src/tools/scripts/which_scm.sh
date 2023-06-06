#!/usr/bin/ksh -p
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
# Copyright 2023 Bill Sommerfeld
#

# which_scm outputs two strings: one identifying the SCM in use, and
# the second giving the root directory for the SCM, if known, or just
# the current working directory if not known.

# There are three distinct types of SCM systems we can detect.  The first
# type have a control directory per directory (RCS and SCCS), with no other
# structure.  The second type have a control directory in each subdirectory
# within a tree (CVS and SVN).  The last type have a single control
# directory at the top of the tree (Teamware and Mercurial).

# If the common CODEMGR_WS variable is set, then we look there for the
# SCM type and bail out if we can't determine it.

# If that variable is not set, then we start in the current directory
# and work our way upwards until we find the top of the tree or we
# encounter an error.

# We do handle nested SCM types, and report the innermost one, but if
# you nest one of the "second type" systems within another instance of
# itself, we'll keep going upwards and report the top of the nested
# set of trees.


# Check for well-known tree-type source code management (SCM) systems.
function primary_type
{
	typeset scmid

	[ -d "$1/Codemgr_wsdata" ] && scmid="$scmid teamware"
	[ -d "$1/.hg" ] && scmid="$scmid mercurial"
	[ -d "$1/CVS" ] && scmid="$scmid cvs"
	[ -d "$1/.svn" ] && scmid="$scmid subversion"
	[ -d "$1/.git" ] && scmid="$scmid git"
	[ -f "$1/.git" ] && scmid="$scmid git"
	echo $scmid
}

if [[ -n "$CODEMGR_WS" ]]; then
	if [[ ! -d "$CODEMGR_WS" ]]; then
		print -u2 "which_scm: $CODEMGR_WS is not a directory."
		exit 1
	fi
	set -- $(primary_type "$CODEMGR_WS")
	if [[ $# != 1 ]]; then
		set -- unknown
	fi
	echo "$1 $CODEMGR_WS"
	exit 0
fi

ORIG_CWD=$(pwd)

if [[ -d RCS ]]; then
	echo "rcs $ORIG_CWD"
	exit 0
fi

# If it's not Teamware, it could just be local SCCS.
LOCAL_TYPE=
[[ -d SCCS ]] && LOCAL_TYPE="sccs"

# Scan upwards looking for top of tree.
DIR=$ORIG_CWD
CWD_TYPE=$(primary_type "$DIR")
SCM_TYPE=
while [[ "$DIR" != / ]]; do
	set -- $(primary_type "$DIR")
	if [[ $# > 1 ]]; then
		echo "unknown $ORIG_CWD"
		exit 0
	fi
	SCM_TYPE="$1"
	# We're done searching if we hit either a change in type or the top
	# of a "third type" control system.
	if [[ "$SCM_TYPE" != "$CWD_TYPE" || "$SCM_TYPE" == git || \
	    "$SCM_TYPE" == mercurial || "$SCM_TYPE" == teamware ]]; then
		break
	fi
	PREVDIR="$DIR"
	DIR=$(dirname "$DIR")
done

# We assume here that the system root directory isn't the root of the SCM.

# Check for the "second type" of repository.  In all cases, we started
# out in the tree and stepped out on the last iteration, so we want
# $PREVDIR.
if [[ "$CWD_TYPE" == cvs || "$CWD_TYPE" == subversion ]]; then
	echo "$CWD_TYPE $PREVDIR"
	exit 0
fi

# If we still don't know what it is, then check for a local type in the
# original directory.  If none, then we don't know what it is.
if [[ -z "$SCM_TYPE" ]]; then
	if [[ -z "$LOCAL_TYPE" ]]; then
		SCM_TYPE=unknown
	else
		SCM_TYPE=$LOCAL_TYPE
		DIR=$ORIG_CWD
	fi
fi

echo "$SCM_TYPE $DIR"
exit 0
