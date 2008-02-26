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
set $iosize=1m
set $nthreads=1

set mode quit alldone

define fileset name=srcfiles,path=$dir,size=$filesize,entries=$nfiles,dirwidth=$dirwidth,prealloc
define fileset name=destfiles,path=$dir,size=$filesize,entries=$nfiles,dirwidth=$dirwidth

define process name=filereader,instances=1
{
  thread name=filereaderthread,memsize=10m,instances=$nthreads
  {
    flowop openfile name=openfile1,filesetname=srcfiles,fd=1
    flowop readwholefile name=readfile1,fd=1,iosize=$iosize
    flowop createfile name=createfile2,filesetname=destfiles,fd=2
    flowop writewholefile name=writefile2,filesetname=destfiles,fd=2,srcfd=1,iosize=$iosize
    flowop closefile name=closefile1,fd=1
    flowop closefile name=closefile2,fd=2
  }
}

echo  "Bringover Version 2.2 personality successfully loaded"
usage "Usage: set \$dir=<dir>"
usage "       set \$filesize=<size>   defaults to $filesize"
usage "       set \$nfiles=<value>    defaults to $nfiles"
usage "       set \$iosize=<size>     defaults to $iosize"
usage "       set \$dirwidth=<value>  defaults to $dirwidth"
usage "       set \$nthreads=<value>  defaults to $nthreads"
usage " "
usage "       run 0"
