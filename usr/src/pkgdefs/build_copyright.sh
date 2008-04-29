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
# ident	"%Z%%M%	%I%	%E% SMI"
#

LDELIM="\n--------------------------------------------------------------------\n\n"
DIGEST=/usr/bin/digest
dest=copyright

#
# Destination file should not be under version control
#
if [ -f SCCS/s.${dest} ]; then
	echo "${dest} should not be under SCCS control">&2
	exit 1
fi	

#
# We must have a list of files to start with
#
if [ $# -eq 0 ]; then
	echo "${dest} may not be empty">&2
	exit 2
fi

echo "building `basename ${PWD}` ${dest} file from $*"
rm -f ${dest}
typeset -A encountered
delimiter=""
for f; do
	if [ ! -s "${f}" ]; then
		echo "${f} should not be empty">&2
		exit 3
	fi
	hash=`${DIGEST} -a sha1 < $f`
	if [ -z "${encountered[${hash}]}" ]; then
		encountered[${hash}]="yes"
		( print "${delimiter}\c"; cat ${f}; ) >> ${dest}
		delimiter="${LDELIM}"
	fi
done

exit 0
