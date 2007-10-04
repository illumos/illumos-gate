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
set $iosize=2k
set $count=65536
set $filesize=1g
set $iters=1

define fileset name=bigfile,path=$dir,size=$filesize,entries=$nthreads,dirwidth=1024,prealloc

define process name=filewriter,instances=1
{
  thread name=filewriterthread,memsize=10m,instances=$nthreads
  {
    flowop write name=write-file,filesetname=bigfile,random,dsync,iosize=$iosize,fd=1,iters=$iters
    flowop finishoncount name=finish,value=$count
  }
}

echo  "FileMicro-WriteRandFsync Version 2.0 personality successfully loaded"
usage "Usage: set \$dir=<dir>"
usage "       set \$filesize=<size>  defaults to $filesize"
usage "       set \$iosize=<size>    defaults to $iosize"
usage "       set \$count=<value>    defaults to $count"
usage "       set \$nthreads=<value> defaults to $nthreads"
usage "       set \$iters=<value>    defaults to $iters"
usage " "
usage "       run runtime (e.g. run 60)"
