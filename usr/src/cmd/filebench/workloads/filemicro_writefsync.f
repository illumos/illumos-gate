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

# Single threaded appends/writes (8KB I/Os) to a 1GB file.
# Each loop iteration does a fsync after 1250 ($iters) appends.
# Stops after 128K ($count) appends have been done.

set $dir=/tmp
set $count=128k
set $iosize=8k
set $iters=1250
set $nthreads=1

define file name=bigfile,path=$dir,size=0,prealloc

define process name=filecreater,instances=1
{
  thread name=filecreaterthread,memsize=10m,instances=$nthreads
  {
    flowop appendfile name=append-file,filename=bigfile,iosize=$iosize,iters=$iters
    flowop fsync name=sync-file
    flowop finishoncount name=finish,value=$count
  }
}

echo  "FileMicro-WriteFsync Version 2.1 personality successfully loaded"
usage "Usage: set \$dir=<dir>"
usage "       set \$count=<value>    defaults to $count"
usage "       set \$iosize=<size>    defaults to $iosize"
usage "       set \$iters=<value>    defaults to $iters"
usage "       set \$nthreads=<value> defaults to $nthreads"
usage " "
usage "       run runtime (e.g. run 60)"
