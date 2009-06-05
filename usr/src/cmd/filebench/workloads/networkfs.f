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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# $dir - directory for datafiles
# $eventrate - event generator rate (0 == free run)
# $nfiles - number of data files
# $nthreads - number of worker threads

set $dir=/tmp
set $cached=false
set $eventrate=10
set $meandirwidth=20
set $nthreads=1
set $nfiles=10000
set $sync=false
set $totalfiles=$nfiles * $eventrate

eventgen rate=$eventrate

define randvar name=$wrtiosize, type=tabular, min=1k, round=1k, randtable =
{{ 0,   1k,    7k},
 {50,   9k,   15k},
 {14,  17k,   23k},
 {14,  33k,   39k},
 {12,  65k,   71k},
 {10, 129k,  135k}
}

define randvar name=$rdiosize, type=tabular, min=8k, round=1k, randtable =
{{85,   8k,   8k},
 { 8,  17k,  23k},
 { 4,  33k,  39k},
 { 2,  65k,  71k},
 { 1, 129k, 135k}
}

define randvar name=$filesize, type=tabular, min=1k, round=1k, randtable =
{{33,   1k,    1k},
 {21,   1k,    3k},
 {13,   3k,    5k},
 {10,   5k,   11k},
 {08,  11k,   21k},
 {05,  21k,   43k},
 {04,  43k,   85k},
 {03,  85k,  171k},
 {02, 171k,  341k},
 {01, 341k, 1707k}
}

define randvar name=$fileidx, type=gamma, min=0, gamma=100

define fileset name=bigfileset,path=$dir,size=$filesize,entries=$totalfiles,dirwidth=$meandirwidth,prealloc=60,cached=$cached

define flowop name=rmw, $filesetrmw
{
  flowop openfile name=openfile1,filesetname=$filesetrmw,indexed=$fileidx,fd=1
  flowop readwholefile name=readfile1,iosize=$rdiosize,fd=1
  flowop createfile name=newfile2,filesetname=$filesetrmw,indexed=$fileidx,fd=2
  flowop writewholefile name=writefile2,fd=2,iosize=$wrtiosize,srcfd=1
  flowop closefile name=closefile1,fd=1
  flowop closefile name=closefile2,fd=2
  flowop deletefile name=deletefile1,fd=1
}

define flowop name=launch, $filesetlch
{
  flowop openfile name=openfile3,filesetname=$filesetlch,indexed=$fileidx,fd=3
  flowop readwholefile name=readfile3,iosize=$rdiosize,fd=3
  flowop openfile name=openfile4,filesetname=$filesetlch,indexed=$fileidx,fd=4
  flowop readwholefile name=readfile4,iosize=$rdiosize,fd=4
  flowop closefile name=closefile3,fd=3
  flowop openfile name=openfile5,filesetname=$filesetlch,indexed=$fileidx,fd=5
  flowop readwholefile name=readfile5,iosize=$rdiosize,fd=5
  flowop closefile name=closefile4,fd=4
  flowop closefile name=closefile5,fd=5
}

define flowop name=appnd, $filesetapd
{
  flowop openfile name=openfile6,filesetname=$filesetapd,indexed=$fileidx,fd=6
  flowop appendfilerand name=appendfilerand6,iosize=$wrtiosize,fd=6
  flowop closefile name=closefile6,fd=6
}

define process name=netclient,instances=1
{
  thread name=fileuser,memsize=10m,instances=$nthreads
  {
    flowop launch name=launch1, iters=1, $filesetlch=bigfileset
    flowop rmw name=rmw1, iters=6, $filesetrmw=bigfileset
    flowop appnd name=appnd1, iters=3, $filesetapd=bigfileset
    flowop statfile name=statfile1,filesetname=bigfileset,indexed=$fileidx
    flowop eventlimit name=ratecontrol
  }
}

echo  "NetworkFileServer Version 1.0 personality successfully loaded"
usage "Usage: set \$dir=<dir>            defaults to $dir"
usage "       set \$cached=<bool>        defaults to $cached"
usage "       set \$eventrate=<value>    defaults to $eventrate"
usage "       set \$wrtiosize.type=<type>   defaults to $wrtiosize.type"
usage "       set \$wrtiosize.randsrc=<src> defaults to $wrtiosize.randsrc"
usage "       set \$rdiosize.type=<type>   defaults to $rdiosize.type"
usage "       set \$rdiosize.randsrc=<src> defaults to $rdiosize.randsrc"
usage "       set \$filesize.type=<type>   defaults to $filesize.type"
usage "       set \$filesize.randsrc=<src> defaults to $filesize.randsrc"
usage "       set \$nfiles=<value>       defaults to $nfiles"
usage "       set \$nthreads=<value>     defaults to $nthreads"
usage "       set \$sync=<bool>          defaults to $sync"
usage " "
usage "       run runtime (e.g. run 60)"
