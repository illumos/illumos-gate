#!/bin/sh
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
# Copyright (c) 1993 by Sun Microsystems, Inc.

#ident	"%Z%%M%	%I%	%E% SMI"
#
# Check shared NFS filesystems for .nfs* files that 
# are more than a week old.
#
# These files are created by NFS clients when an open file
# is removed. To preserve some semblance of Unix semantics
# the client renames the file to a unique name so that the
# file appears to have been removed from the directory, but
# is still usable by the process that has the file open.

if [ ! -s /etc/dfs/sharetab ]; then exit ; fi

# Get all NFS filesystems exported with read-write permission.

DIRS=`/usr/bin/nawk '($3 != "nfs") { next }
	($4 ~ /^rw$|^rw,|^rw=|,rw,|,rw=|,rw$/) { print $1; next }
	($4 !~ /^ro$|^ro,|^ro=|,ro,|,ro=|,ro$/) { print $1 }' /etc/dfs/sharetab`

for dir in $DIRS
do
        find $dir -type f -name .nfs\* -mtime +7 -mount -exec rm -f {} \;
done
