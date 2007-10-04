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

# $iosize - iosize for database block access
# $dir - directory for datafiles
# $nshadows - number of shadow processes
# $ndbwriters - number of database writers
#
set $dir=/tmp
set $runtime=30
set $iosize=2k
set $nshadows=200
set $ndbwriters=10
set $usermode=200000
set $filesize=10m
set $memperthread=1m
set $workingset=0
set $cached=0
set $logfilesize=10m
set $nfiles=10
set $nlogfiles=1
set $directio=0

# Define a datafile and logfile
define fileset name=datafiles,path=$dir,size=$filesize,filesizegamma=0,entries=$nfiles,dirwidth=1024,prealloc=100,cached=$cached,reuse
define fileset name=logfile,path=$dir,size=$logfilesize,filesizegamma=0,entries=$nlogfiles,dirwidth=1024,prealloc=100,cached=$cached,reuse

define process name=lgwr,instances=1
{
  thread name=lgwr,memsize=$memperthread,useism
  {
    flowop aiowrite name=lg-write,filesetname=logfile,
        iosize=256k,random,directio=$directio
    flowop aiowait name=lg-aiowait
    flowop semblock name=lg-block,value=3200,highwater=1000
  }
}

# Define database writer processes
define process name=dbwr,instances=$ndbwriters
{
  thread name=dbwr,memsize=$memperthread,useism
  {
    flowop aiowrite name=dbwrite-a,filesetname=datafiles,
        iosize=$iosize,workingset=$workingset,random,iters=100,opennext,directio=$directio
    flowop hog name=dbwr-hog,value=10000
    flowop semblock name=dbwr-block,value=1000,highwater=2000
    flowop aiowait name=dbwr-aiowait
  }
}


define process name=shadow,instances=$nshadows
{
  thread name=shadow,memsize=$memperthread,useism
  {
    flowop read name=shadowread,filesetname=datafiles,
      iosize=$iosize,workingset=$workingset,random,opennext,directio=$directio
    flowop hog name=shadowhog,value=$usermode
    flowop sempost name=shadow-post-lg,value=1,target=lg-block,blocking
    flowop sempost name=shadow-post-dbwr,value=1,target=dbwr-block,blocking
    flowop eventlimit name=random-rate
  }
}

echo "OLTP Version 2.0 personality successfully loaded"
usage "Usage: set \$dir=<dir>"
usage " "
usage "       set \$filesize=<size>   defaults to $filesize, n.b. there are ten files of this size"
usage " "
usage "       set \$logfilesize=<size> defaults to $logfilesize, n.b. there is one file of this size"
usage " "
usage "       set \$iosize=<value>    defaults to $iosize, typically 2k or 8k"
usage " "
usage "       set \$cached=<bool>     defaults to $cached"
usage " "
usage "       set \$memperthread=<value> defaults to $memperthread"
usage " "
usage "       set \$directio=<value>  defaults to $directio"
usage " "
usage "       run runtime (e.g. run 60)"
usage " "
usage "Note - total filesize should be at least 2x physical memory size for conforming test)"
usage "       i.e. if physmem = 4G, set filesize to 4G * 2 / 10, or 800m" 
usage " "
usage "Note - this workload needs at least 512MB of of memory"
usage " "

