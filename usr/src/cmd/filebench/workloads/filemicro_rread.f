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

# Single threaded random reads (2KB I/Os) on a 1GB file.
# Stops after 128MB ($bytes) has been read.

set $dir=/tmp
set $bytes=128m
set $cached=false
set $filesize=1g
set $iosize=2k
set $iters=1
set $nthreads=1

define file name=bigfile1,path=$dir,size=$filesize,prealloc,reuse,cached=$cached

define process name=filereader,instances=1
{
  thread name=filereaderthread,memsize=10m,instances=$nthreads
  {
    flowop read name=write-file,filesetname=bigfile1,random,iosize=$iosize,iters=$iters
    flowop finishonbytes name=finish,value=$bytes
  }
}

echo  "FileMicro-ReadRand Version 2.2 personality successfully loaded"
usage "Usage: set \$dir=<dir>"
usage "       set \$bytes=<value>     defaults to $bytes"
usage "       set \$cached=<bool>     defaults to $cached"
usage "       set \$filesize=<size>   defaults to $filesize"
usage "       set \$iters=<value>     defaults to $iters"
usage "       set \$iosize=<size>     defaults to $iosize"
usage "       set \$nthreads=<value>  defaults to $nthreads"
usage " "
usage "       run runtime (e.g. run 60)"
