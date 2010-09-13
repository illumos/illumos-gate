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

set $dir=/tmp
set $directio=false
set $iosize=1m
set $nthreads=1

define file name=largefile1,path=$dir,prealloc

define process name=seqwrite,instances=1
{
  thread name=seqwrite,memsize=10m,instances=$nthreads
  {
    flowop write name=seqwrite,filename=largefile1,iosize=$iosize,directio=$directio
    flowop bwlimit name=limit
  }
}

echo  "Single Stream Write Version 2.2 personality successfully loaded"
usage "Usage: set \$dir=<dir>"
usage "       set \$directio=<bool>    defaults to $directio"
usage "       set \$iosize=<value>     defaults to $iosize"
usage "       set \$nthreads=<value>   defaults to $nthreads"
usage " "
usage "       run runtime (e.g. run 60)"
