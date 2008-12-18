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
# This workloads emulates a video server. It has two filesets, one of videos
# being actively served, and one of videos availabe but currently inactive
# (passive). However, one thread, vidwriter, is writing new videos to replace
# no longer viewed videos in the passive set. Meanwhile $nthreads threads are
# serving up videos from the activevids fileset. If the desired rate is R mb/s,
# and $nthreads is set to T, then set the $srvbwrate to R * T to get the
# desired rate per video stream. The video replacement rate of one video
# file per replacement interval, is set by $repintval which defaults to
# 10 seconds. Thus the write bandwidth will be set as $filesize/$repintval.

set $dir=/tmp
set $filesize=10g
set $nthreads=48
set $numactivevids=32
set $numpassivevids=194
set $reuseit=false
set $readiosize=256k
set $writeiosize=1m
#
set $passvidsname=passivevids
set $actvidsname=activevids
#
set $repintval=10
set $srvbwrate=96

eventgen rate=$srvbwrate

define fileset name=$actvidsname,path=$dir,size=$filesize,entries=$numactivevids,dirwidth=4,prealloc,paralloc,reuse=$reuseit
define fileset name=$passvidsname,path=$dir,size=$filesize,entries=$numpassivevids,dirwidth=20,prealloc=50,paralloc,reuse=$reuseit

define process name=vidwriter,instances=1
{
  thread name=vidwriter,memsize=10m,instances=1
  {
    flowop deletefile name=vidremover,filesetname=$passvidsname
    flowop createfile name=wrtopen,filesetname=$passvidsname,fd=1
    flowop writewholefile name=newvid,iosize=$writeiosize,fd=1,srcfd=1
    flowop closefile name=wrtclose, fd=1
    flowop delay name=replaceinterval, value=$repintval
  }
}

define process name=vidreaders,instances=1
{
  thread name=vidreaders,memsize=10m,instances=$nthreads
  {
    flowop read name=vidreader,filesetname=$actvidsname,iosize=$readiosize
    flowop bwlimit name=serverlimit, target=vidreader
  }
}

echo  "Video Server Version 1.0 personality successfully loaded"
usage "Usage: set \$dir=<dir>              defaults to $dir"
usage "       set \$filesize=<size>        defaults to $filesize"
usage "       set \$nthreads=<value>       defaults to $nthreads"
usage "       set \$writeiosize=<value>    defaults to $writeiosize"
usage "       set \$readiosize=<value>     defaults to $readiosize"
usage "       set \$numactivevids=<value>  defaults to $numactivevids"
usage "       set \$numpassivevids=<value> defaults to $numpassivevids"
usage "       set \$srvbwrate=<value>      defaults to $srvbwrate"
usage " "
usage "       run runtime (e.g. run 60)"

