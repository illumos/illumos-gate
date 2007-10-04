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

# 4- Sequential read(32K) of a 1G file, cached 
# 5- Sequential read(32K) of a 1G file, uncached 

set $dir=/tmp
set $nthreads=1
set $iosize=1m
set $filesize=1g
set $cached=0

define fileset name=bigfileset,path=$dir,size=$filesize,entries=$nthreads,dirwidth=1024,prealloc=100,cached=$cached

define process name=filereader,instances=1
{
  thread name=filereaderthread,memsize=10m,instances=$nthreads
  {
    flowop read name=append-file,filesetname=bigfileset,iosize=$iosize,fd=1
  }
}

echo  "FileMicro-SeqRead Version 2.0 personality successfully loaded"
usage "Usage: set \$dir=<dir>"
usage "       set \$iosize=<size>    defaults to $iosize"
usage "       set \$filesize=<size>  defaults to $filesize"
usage "       set \$nthreads=<value> defaults to $nthreads"
usage "       set \$cached=<bool>    defaults to $cached"
usage " "
usage "       run runtime (e.g. run 60)"
