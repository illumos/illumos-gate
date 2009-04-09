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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.

# Single threaded appends/writes (I/Os of random size in the range
# of [1B - 8KB]) to a 1GB file.
# Stops after 128K ($count) writes have been done.

set $dir=/tmp
set $cached=false
set $count=128k
set $iosize=8k
set $nthreads=1
set $sync=false

define file name=bigfile,path=$dir,size=0,prealloc,cached=$cached

define process name=filewriter,instances=1
{
  thread name=filewriterthread,memsize=10m,instances=$nthreads
  {
    flowop openfile name=open-file,filename=bigfile,fd=1
    flowop appendfilerand name=appendrand-file,dsync=$sync,iosize=$iosize,fd=1,iters=$count
    flowop closefile name=close,fd=1
    flowop finishoncount name=finish,value=1
  }
}

echo  "FileMicro-SeqWriteRand Version 2.2 personality successfully loaded"
usage "Usage: set \$dir=<dir>"
usage "       set \$cached=<bool>    defaults to $cached"
usage "       set \$count=<bool>     defaults to $count"
usage "       set \$iosize=<size>    defaults to $iosize"
usage "       set \$nthreads=<value> defaults to $nthreads"
usage "       set \$sync=<bool>      defaults to $sync"
usage " "
usage "       run runtime (e.g. run 60)"
