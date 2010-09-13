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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

# findcrypto cred_file
#
# Utility to find cryptographic modules in the proto area.  Prints out
# one line for each binary, using the form
#
#   cred path
#
# where "path" identifies the binary (relative to $ROOT), and "cred"
# says how the binary should get signed.
#
# The cred_file argument is the same as for signproto.sh.
#

# Directories in proto area that may contain crypto objects
DIRS="platform kernel usr/lib/security"

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
	while [[ i -lt n ]]; do
		if expr "$s" : ".*${regex[i]}" >/dev/null; then
			echo "${cred[i]} $f"
			break
		fi
		(( i = i + 1 ))
	done
done

exit 0
