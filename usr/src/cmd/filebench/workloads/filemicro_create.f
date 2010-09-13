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

# Simple way to create a file.  Start off with a zero length file, and issue
# 1024 ($count) 1MB appends.

set $dir=/tmp
set $count=1024
set $iosize=1m
set $nthreads=1
set $sync=false

define file name=largefile,path=$dir,size=0,prealloc

define process name=filecreater,instances=1
{
  thread name=filecreaterthread,memsize=10m,instances=$nthreads
  {
    flowop appendfile name=append-file,filename=largefile,dsync=$sync,iosize=$iosize
    flowop finishoncount name=finish,value=$count
  }
}

echo  "FileMicro-Create Version 2.1 personality successfully loaded"
usage "Usage: set \$dir=<dir>"
usage "       set \$count=<value>    defaults to $count"
usage "       set \$iosize=<size>    defaults to $iosize"
usage "       set \$nthreads=<value> defaults to $nthreads"
usage "       set \$sync=<bool>      defaults to $sync"
usage " "
usage "       run runtime (e.g. run 60)"
