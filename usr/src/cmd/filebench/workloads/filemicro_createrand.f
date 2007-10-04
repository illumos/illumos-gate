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

#  3- open() and allocation of a 1GB file with write()
#     of size picked uniformly in [1K,8K] range and issuing
#     fsync() every 10MB.
#     fm_create8k


set $dir=/tmp
set $nthreads=1
set $iosize=1m
set $count=1280
set $bytes=1g
set $sync=0

define fileset name=bigfileset,path=$dir,size=0,entries=128,dirwidth=1024,prealloc=100

define process name=filecreater,instances=1
{
  thread name=filecreaterthread,memsize=10m,instances=$nthreads
  {
    flowop appendfilerand name=append-file,filesetname=bigfileset,dsync=$sync,iosize=$iosize,fd=1
    flowop fsync name=sync,fd=1
    flowop finishonbytes name=finish,value=$bytes
  }
}

echo  "FileMicro-CreateRand Version 2.0 personality successfully loaded"
usage "Usage: set \$dir=<dir>"
usage "       set \$iosize=<size>    defaults to $iosize"
usage "       set \$bytes=<value>    defaults to $bytes"
usage "       set \$count=<value>    defaults to $count"
usage "       set \$nthreads=<value> defaults to $nthreads"
usage "       set \$sync=<bool>      defaults to $sync"
usage " "
usage "       run runtime (e.g. run 60)"
