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

# Single threaded asynchronous random writes (8KB I/Os) on a 1GB file.
# A fsync is issued after 16K ($iters) worth of writes.
# Stops after one ($count) fsync.

set $dir=/tmp
set $cached=false
set $count=1
set $filesize=1g
set $iosize=8k
set $iters=16384
set $nthreads=1

define file name=bigfile,path=$dir,size=$filesize,prealloc,cached=$cached

define process name=filewriter,instances=1
{
  thread name=filewriterthread,memsize=10m,instances=$nthreads
  {
    flowop write name=write-file,filename=bigfile,random,iosize=$iosize,iters=$iters
    flowop fsync name=sync-file
    flowop finishoncount name=finish,value=$count
  }
}

echo  "FileMicro-WriteRandFsync Version 2.1 personality successfully loaded"
usage "Usage: set \$dir=<dir>"
usage "       set \$cached=<bool>    defaults to $cached"
usage "       set \$count=<value>    defaults to $count"
usage "       set \$filesize=<size>  defaults to $filesize"
usage "       set \$iosize=<size>    defaults to $iosize"
usage "       set \$iters=<value>    defaults to $iters"
usage "       set \$nthreads=<value> defaults to $nthreads"
usage " "
usage "       run runtime (e.g. run 60)"
