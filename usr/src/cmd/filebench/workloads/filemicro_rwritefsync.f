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

# 128M worth of random 8K-aligned write(2) to a 1G file; followed by fsync(); cached.

set $dir=/tmp
set $nthreads=1
set $iosize=8k
set $count=1
set $iters=16384
set $filesize=1g
set $cached=0

define fileset name=bigfileset,path=$dir,size=$filesize,entries=$nthreads,dirwidth=1024,prealloc=100,cached=$cached

define process name=filewriter,instances=1
{
  thread name=filewriterthread,memsize=10m,instances=$nthreads
  {
    flowop write name=write-file,filesetname=bigfileset,random,iosize=$iosize,fd=1,iters=$iters
    flowop fsync name=sync-file,fd=1
    flowop finishoncount name=finish,value=$count
  }
}

echo  "FileMicro-WriteRandFsync Version 2.0 personality successfully loaded"
usage "Usage: set \$dir=<dir>"
usage "       set \$iosize=<size>    defaults to $iosize"
usage "       set \$count=<value>    defaults to $count"
usage "       set \$nthreads=<value> defaults to $nthreads"
usage "       set \$cached=<value>   defaults to $cached"
usage " "
usage "       run runtime (e.g. run 60)"
