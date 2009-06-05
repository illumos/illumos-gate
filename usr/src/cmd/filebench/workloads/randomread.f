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
#
# $dir - directory for datafiles
# $eventrate - event generator rate (0 == free run)
# $filesize - size of data file
# $iosize - size of each read
# $nthreads - number of worker threads

set $dir=/tmp
set $eventrate=0
set $filesize=1m
set $iosize=8k
set $nthreads=1
set $workingset=0
set $directio=0

eventgen rate=$eventrate

define file name=largefile1,path=$dir,size=$filesize,prealloc,reuse,paralloc

define process name=rand-read,instances=1
{
  thread name=rand-thread,memsize=5m,instances=$nthreads
  {
    flowop read name=rand-read1,filename=largefile1,iosize=$iosize,random,workingset=$workingset,directio=$directio
    flowop eventlimit name=rand-rate
  }
}

echo "Random Read Version 2.1 IO personality successfully loaded"
usage "Usage: set \$dir=<dir>         defaults to $dir"
usage "       set \$eventrate=<value> defaults to $eventrate"
usage "       set \$filesize=<size>   defaults to $filesize"
usage "       set \$iosize=<value>    defaults to $iosize"
usage "       set \$nthreads=<value>  defaults to $nthreads"
usage "       set \$workingset=<value>  defaults to $workingset"
usage "       set \$directio=<bool>   defaults to $directio"
usage "       run runtime (e.g. run 60)"
