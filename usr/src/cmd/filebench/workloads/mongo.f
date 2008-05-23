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

set $dir=/tmp
set $nfiles=1000
set $dirwidth=20
set $filesize=16k
set $nthreads=1
set $meaniosize=16k
set $readiosize=1m

set mode quit firstdone

define fileset name=postset,path=$dir,size=$filesize,entries=$nfiles,dirwidth=$dirwidth,prealloc,paralloc
define fileset name=postsetdel,path=$dir,size=$filesize,entries=$nfiles,dirwidth=$dirwidth,prealloc,paralloc

define process name=filereader,instances=1
{
  thread name=filereaderthread,memsize=10m,instances=$nthreads
  {
    flowop openfile name=openfile1,filesetname=postset,fd=1
    flowop appendfilerand name=appendfilerand1,iosize=$meaniosize,fd=1
    flowop closefile name=closefile1,fd=1
    flowop openfile name=openfile2,filesetname=postset,fd=1
    flowop readwholefile name=readfile1,fd=1,iosize=$readiosize
    flowop closefile name=closefile2,fd=1
    flowop deletefile name=deletefile1,filesetname=postsetdel
  }
}

echo  "Mongo-like Version 2.3 personality successfully loaded"
usage "Usage: set \$dir=<dir>          defaults to $dir"
usage "       set \$filesize=<size>    defaults to $filesize"
usage "       set \$nfiles=<value>     defaults to $nfiles"
usage "       set \$dirwidth=<value>   defaults to $dirwidth"
usage "       set \$nthreads=<value>   defaults to $nthreads"
usage "       set \$meaniosize=<value> defaults to $meaniosize"
usage "       set \$readiosize=<size>  defaults to $readiosize"
usage " "
usage "       run"
