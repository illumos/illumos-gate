#!/bin/ksh
#
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

# signproto cred_file
#
# Utility to find cryptographic modules in the proto area and
# sign them using signit. Since the binaries have already been
# signed (using development keys) during the build process,
# we determine the correct signing credential to use based on
# the existing signature. The cred_file argument contains a
# list of signing server credentials and the corresponding
# regular expressions to match against the file signatures.

# Directories in proto area that may contain crypto objects
DIRS="platform kernel usr/lib/security"

# Get absolute path of current directory; used later to invoke signit
cd .
dir=`dirname $0`
dir=`[[ $dir = /* ]] && print $dir || print $PWD/$dir`

# Read list of credentials and regular expressions
n=0
grep -v "^#" $1 | while read c r
do
	cred[$n]=$c
	regex[$n]=$r
	(( n = n + 1 ))
done

# Search proto area for crypto modules
cd $ROOT
find $DIRS -type f -print | while read f; do
	s=`elfsign list -f signer -e $f 2>/dev/null`
	if [[ $? != 0 ]]; then 
		continue
	fi
	# Determine credential based on signature
	i=0
	while [[ i -lt n ]]
	do
		if expr "$s" : ".*${regex[i]}" >/dev/null; then
			echo "${cred[i]} $f"
			break
		fi
		(( i = i + 1 ))
	done
done | $dir/signit -i $ROOT -l ${CODESIGN_USER:-${LOGNAME}}

if [ $? != 0 ]; then
	echo "ERROR failure in signing operation"
fi
