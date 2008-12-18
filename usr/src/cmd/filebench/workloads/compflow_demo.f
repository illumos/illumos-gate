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

set $dir=/tmp
set $nfiles=700
set $meandirwidth=20
set $filesize=128k
set $nthreads=10
set $meaniosize=16k

define fileset name=bigfileset,path=$dir,size=$filesize,entries=$nfiles,dirwidth=$meandirwidth,prealloc=80, paralloc

define fileset name=u2fileset,path=$dir,size=$filesize,entries=$nfiles,dirwidth=$meandirwidth,prealloc=80, paralloc

define fileset name=u3fileset,path=$dir,size=$filesize,entries=$nfiles,dirwidth=$meandirwidth,prealloc=80, paralloc

define flowop name=readwrite, $fileset
{
  flowop openfile name=openfile4,filesetname=$fileset,fd=1
  flowop openfile name=openfile5,filesetname=$fileset,fd=2
  flowop readwholefile name=readfile1,fd=1
  flowop writewholefile name=writefile1,fd=2,srcfd=1
  flowop closefile name=closefile4,fd=1
  flowop closefile name=closefile5,fd=2
}

define flowop name=dowork, $filesetnm, $rwiters
{
  flowop createfile name=createfile1,filesetname=$filesetnm,fd=1
  flowop appendfilerand name=appendfilerand1,iosize=$meaniosize,fd=1
  flowop closefile name=closefile1,fd=1
  flowop readwrite name=rw1, iters=$rwiters, $fileset=$filesetnm
  flowop deletefile name=deletefile1,filesetname=$filesetnm
  flowop statfile name=statfile1,filesetname=$filesetnm
}

define process name=filereader1,instances=1
{
  thread name=user1,memsize=10m,instances=$nthreads
  {
    flowop dowork name=dowork1, iters=1, $rwiters=5, $filesetnm=bigfileset
  }

  thread name=user2,memsize=10m,instances=$nthreads
  {
    flowop dowork name=dowork2, iters=1, $rwiters=4, $filesetnm=u2fileset
  }

  thread name=user3,memsize=10m,instances=$nthreads
  {
    flowop dowork name=dowork3, iters=1, $rwiters=3, $filesetnm=u3fileset
  }
}

echo  "CompFlow_Demo Version 1.1 personality successfully loaded"
usage "Usage: set \$dir=<dir>          defaults to $dir"
usage "       set \$filesize=<size>    defaults to $filesize"
usage "       set \$nfiles=<value>     defaults to $nfiles"
usage "       set \$nthreads=<value>   defaults to $nthreads"
usage "       set \$meaniosize=<value> defaults to $meaniosize"
usage "       set \$meandirwidth=<size> defaults to $meandirwidth"
usage "(sets mean dir width and dir depth is calculated as log (width, nfiles)"
usage " "
usage "       run runtime (e.g. run 60)"
