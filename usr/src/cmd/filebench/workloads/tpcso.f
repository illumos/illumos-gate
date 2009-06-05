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
# $iosize - iosize for database block access
# $nshadows - number of shadow processes
# $ndbwriters - number of database writers

set $dir=/tmp
set $eventrate=0
set $iosize=2k
set $nshadows=200
set $ndbwriters=10
set $runtime=30
set $usermode=20000
set $memperthread=1m

debug 1
eventgen rate=$eventrate

# Define a datafile and logfile
define file name=aux.df,path=$dir,size=251m,reuse,prealloc,paralloc
define file name=control_001,path=$dir,size=2m,reuse,prealloc,paralloc
define file name=cust_0_0,path=$dir,size=6704m,reuse,prealloc,paralloc
define file name=cust_0_1,path=$dir,size=6704m,reuse,prealloc,paralloc
define file name=cust_0_2,path=$dir,size=6704m,reuse,prealloc,paralloc
define file name=cust_0_3,path=$dir,size=6704m,reuse,prealloc,paralloc
define file name=dist_0_0,path=$dir,size=31m,reuse,prealloc,paralloc
define file name=hist_0_0,path=$dir,size=3002m,reuse,prealloc,paralloc
define file name=icust1_0_0,path=$dir,size=4943m,reuse,prealloc,paralloc
define file name=icust2_0_0,path=$dir,size=4943m,reuse,prealloc,paralloc
define file name=idist_0_0,path=$dir,size=11m,reuse,prealloc,paralloc
define file name=iitem_0_0,path=$dir,size=11m,reuse,prealloc,paralloc
define file name=iordr2_0_0,path=$dir,size=1651m,reuse,prealloc,paralloc
define file name=istok_0_0,path=$dir,size=2262m,reuse,prealloc,paralloc
define file name=item_0_0,path=$dir,size=21m,reuse,prealloc,paralloc
define file name=iware_0_0,path=$dir,size=11m,reuse,prealloc,paralloc
define file name=nord_0_0,path=$dir,size=561m,reuse,prealloc,paralloc
define file name=ordr_0_0,path=$dir,size=44301m,reuse,prealloc,paralloc
define file name=roll1,path=$dir,size=2001m,reuse,prealloc,paralloc
define file name=sp_0,path=$dir,size=1001m,reuse,prealloc,paralloc
define file name=stok_0_0,path=$dir,size=8052m,reuse,prealloc,paralloc
define file name=stok_0_1,path=$dir,size=8052m,reuse,prealloc,paralloc
define file name=stok_0_2,path=$dir,size=8052m,reuse,prealloc,paralloc
define file name=stok_0_3,path=$dir,size=8052m,reuse,prealloc,paralloc
define file name=stok_0_4,path=$dir,size=8052m,reuse,prealloc,paralloc
define file name=system_1,path=$dir,size=401m,reuse,prealloc,paralloc
define file name=temp_0_0,path=$dir,size=4943m,reuse,prealloc,paralloc
define file name=temp_0_1,path=$dir,size=4943m,reuse,prealloc,paralloc
define file name=ware_0_0,path=$dir,size=11m,reuse,prealloc,paralloc
define file name=log_1_1,path=$dir,size=1021m,reuse,prealloc,paralloc

# Define database writer processes
define process name=dbwr,instances=$ndbwriters
{
  thread name=dbwr,memsize=$memperthread,useism
  {
	flowop aiowrite name=dbaiowrite-aux.df,filename=aux.df,
                iosize=$iosize,workingset=10g,random,dsync,directio,iters=10
        flowop aiowrite name=dbaiowrite-control_001,filename=control_001,
                iosize=$iosize,workingset=10g,random,dsync,directio,iters=10
        flowop aiowrite name=dbaiowrite-cust_0_0,filename=cust_0_0,
                iosize=$iosize,workingset=10g,random,dsync,directio,iters=10
        flowop aiowrite name=dbaiowrite-cust_0_1,filename=cust_0_1,
                iosize=$iosize,workingset=10g,random,dsync,directio,iters=10
        flowop aiowrite name=dbaiowrite-cust_0_2,filename=cust_0_2,
                iosize=$iosize,workingset=10g,random,dsync,directio,iters=10
        flowop aiowrite name=dbaiowrite-cust_0_3,filename=cust_0_3,
                iosize=$iosize,workingset=10g,random,dsync,directio,iters=10
        flowop aiowrite name=dbaiowrite-dist_0_0,filename=dist_0_0,
                iosize=$iosize,workingset=10g,random,dsync,directio,iters=10
        flowop aiowrite name=dbaiowrite-hist_0_0,filename=hist_0_0,
                iosize=$iosize,workingset=10g,random,dsync,directio,iters=10
        flowop aiowrite name=dbaiowrite-icust1_0_0,filename=icust1_0_0,
                iosize=$iosize,workingset=10g,random,dsync,directio,iters=10
        flowop aiowrite name=dbaiowrite-icust2_0_0,filename=icust2_0_0,
                iosize=$iosize,workingset=10g,random,dsync,directio,iters=10
        flowop aiowrite name=dbaiowrite-idist_0_0,filename=idist_0_0,
                iosize=$iosize,workingset=10g,random,dsync,directio,iters=10
        flowop aiowrite name=dbaiowrite-iitem_0_0,filename=iitem_0_0,
                iosize=$iosize,workingset=10g,random,dsync,directio,iters=10
        flowop aiowrite name=dbaiowrite-iordr2_0_0,filename=iordr2_0_0,
                iosize=$iosize,workingset=10g,random,dsync,directio,iters=10
        flowop aiowrite name=dbaiowrite-istok_0_0,filename=istok_0_0,
                iosize=$iosize,workingset=10g,random,dsync,directio,iters=10
        flowop aiowrite name=dbaiowrite-item_0_0,filename=item_0_0,
                iosize=$iosize,workingset=10g,random,dsync,directio,iters=10
        flowop aiowrite name=dbaiowrite-iware_0_0,filename=iware_0_0,
                iosize=$iosize,workingset=10g,random,dsync,directio,iters=10
        flowop aiowrite name=dbaiowrite-nord_0_0,filename=nord_0_0,
                iosize=$iosize,workingset=10g,random,dsync,directio,iters=10
        flowop aiowrite name=dbaiowrite-ordr_0_0,filename=ordr_0_0,
                iosize=$iosize,workingset=10g,random,dsync,directio,iters=10
        flowop aiowrite name=dbaiowrite-roll1,filename=roll1,
                iosize=$iosize,workingset=10g,random,dsync,directio,iters=10
        flowop aiowrite name=dbaiowrite-sp_0,filename=sp_0,
                iosize=$iosize,workingset=10g,random,dsync,directio,iters=10
        flowop aiowrite name=dbaiowrite-stok_0_0,filename=stok_0_0,
                iosize=$iosize,workingset=10g,random,dsync,directio,iters=10
        flowop aiowrite name=dbaiowrite-stok_0_1,filename=stok_0_1,
                iosize=$iosize,workingset=10g,random,dsync,directio,iters=10
        flowop aiowrite name=dbaiowrite-stok_0_2,filename=stok_0_2,
                iosize=$iosize,workingset=10g,random,dsync,directio,iters=10
        flowop aiowrite name=dbaiowrite-stok_0_3,filename=stok_0_3,
                iosize=$iosize,workingset=10g,random,dsync,directio,iters=10
        flowop aiowrite name=dbaiowrite-stok_0_4,filename=stok_0_4,
                iosize=$iosize,workingset=10g,random,dsync,directio,iters=10
        flowop aiowrite name=dbaiowrite-system_1,filename=system_1,
                iosize=$iosize,workingset=10g,random,dsync,directio,iters=10
        flowop aiowrite name=dbaiowrite-temp_0_0,filename=temp_0_0,
                iosize=$iosize,workingset=10g,random,dsync,directio,iters=10
        flowop aiowrite name=dbaiowrite-temp_0_1,filename=temp_0_1,
                iosize=$iosize,workingset=10g,random,dsync,directio,iters=10
        flowop aiowrite name=dbaiowrite-ware_0_0,filename=ware_0_0,
                iosize=$iosize,workingset=10g,random,dsync,directio,iters=10
	flowop hog name=dbwr-hog,value=10000
	flowop semblock name=dbwr-block,value=100,highwater=10000
	flowop aiowait name=dbwr-aiowait
  }
}

define process name=lgwr,instances=1
{
  thread name=lgwr,memsize=$memperthread,useism
  {
    flowop write name=lg-write,filename=log_1_1,
        iosize=256k,workingset=1g,random,dsync,directio
#   flowop delay name=lg-delay,value=1
    flowop semblock name=lg-block,value=320,highwater=1000
  }
}

define process name=shadow,instances=$nshadows
{
  thread name=shadow,memsize=$memperthread,useism
  {
        flowop read name=shadowread-aux.df,filename=aux.df,
                iosize=$iosize,workingset=10g,random,dsync,directio
        flowop hog name=shadowhog,value=$usermode
        flowop read name=shadowread-control_001,filename=control_001,
                iosize=$iosize,workingset=10g,random,dsync,directio
        flowop hog name=shadowhog,value=$usermode
        flowop read name=shadowread-cust_0_0,filename=cust_0_0,
                iosize=$iosize,workingset=10g,random,dsync,directio
        flowop hog name=shadowhog,value=$usermode
        flowop read name=shadowread-cust_0_1,filename=cust_0_1,
                iosize=$iosize,workingset=10g,random,dsync,directio
        flowop hog name=shadowhog,value=$usermode
        flowop read name=shadowread-cust_0_2,filename=cust_0_2,
                iosize=$iosize,workingset=10g,random,dsync,directio
        flowop hog name=shadowhog,value=$usermode
        flowop read name=shadowread-cust_0_3,filename=cust_0_3,
                iosize=$iosize,workingset=10g,random,dsync,directio
        flowop hog name=shadowhog,value=$usermode
        flowop read name=shadowread-dist_0_0,filename=dist_0_0,
                iosize=$iosize,workingset=10g,random,dsync,directio
        flowop hog name=shadowhog,value=$usermode
        flowop read name=shadowread-hist_0_0,filename=hist_0_0,
                iosize=$iosize,workingset=10g,random,dsync,directio
        flowop hog name=shadowhog,value=$usermode
        flowop read name=shadowread-icust1_0_0,filename=icust1_0_0,
                iosize=$iosize,workingset=10g,random,dsync,directio
        flowop hog name=shadowhog,value=$usermode
        flowop read name=shadowread-icust2_0_0,filename=icust2_0_0,
                iosize=$iosize,workingset=10g,random,dsync,directio
        flowop hog name=shadowhog,value=$usermode
        flowop read name=shadowread-idist_0_0,filename=idist_0_0,
                iosize=$iosize,workingset=10g,random,dsync,directio
        flowop hog name=shadowhog,value=$usermode
        flowop read name=shadowread-iitem_0_0,filename=iitem_0_0,
                iosize=$iosize,workingset=10g,random,dsync,directio
        flowop hog name=shadowhog,value=$usermode
        flowop read name=shadowread-iordr2_0_0,filename=iordr2_0_0,
                iosize=$iosize,workingset=10g,random,dsync,directio
        flowop hog name=shadowhog,value=$usermode
        flowop read name=shadowread-istok_0_0,filename=istok_0_0,
                iosize=$iosize,workingset=10g,random,dsync,directio
        flowop hog name=shadowhog,value=$usermode
        flowop read name=shadowread-item_0_0,filename=item_0_0,
                iosize=$iosize,workingset=10g,random,dsync,directio
        flowop hog name=shadowhog,value=$usermode
        flowop read name=shadowread-iware_0_0,filename=iware_0_0,
                iosize=$iosize,workingset=10g,random,dsync,directio
        flowop hog name=shadowhog,value=$usermode
        flowop read name=shadowread-nord_0_0,filename=nord_0_0,
                iosize=$iosize,workingset=10g,random,dsync,directio
        flowop hog name=shadowhog,value=$usermode
        flowop read name=shadowread-ordr_0_0,filename=ordr_0_0,
                iosize=$iosize,workingset=10g,random,dsync,directio
        flowop hog name=shadowhog,value=$usermode
        flowop read name=shadowread-roll1,filename=roll1,
                iosize=$iosize,workingset=10g,random,dsync,directio
        flowop hog name=shadowhog,value=$usermode
        flowop read name=shadowread-sp_0,filename=sp_0,
                iosize=$iosize,workingset=10g,random,dsync,directio
        flowop hog name=shadowhog,value=$usermode
        flowop read name=shadowread-stok_0_0,filename=stok_0_0,
                iosize=$iosize,workingset=10g,random,dsync,directio
        flowop hog name=shadowhog,value=$usermode
        flowop read name=shadowread-stok_0_1,filename=stok_0_1,
                iosize=$iosize,workingset=10g,random,dsync,directio
        flowop hog name=shadowhog,value=$usermode
        flowop read name=shadowread-stok_0_2,filename=stok_0_2,
                iosize=$iosize,workingset=10g,random,dsync,directio
        flowop hog name=shadowhog,value=$usermode
        flowop read name=shadowread-stok_0_3,filename=stok_0_3,
                iosize=$iosize,workingset=10g,random,dsync,directio
        flowop hog name=shadowhog,value=$usermode
        flowop read name=shadowread-stok_0_4,filename=stok_0_4,
                iosize=$iosize,workingset=10g,random,dsync,directio
        flowop hog name=shadowhog,value=$usermode
        flowop read name=shadowread-system_1,filename=system_1,
                iosize=$iosize,workingset=10g,random,dsync,directio
        flowop hog name=shadowhog,value=$usermode
        flowop read name=shadowread-temp_0_0,filename=temp_0_0,
                iosize=$iosize,workingset=10g,random,dsync,directio
        flowop hog name=shadowhog,value=$usermode
        flowop read name=shadowread-temp_0_1,filename=temp_0_1,
                iosize=$iosize,workingset=10g,random,dsync,directio
        flowop hog name=shadowhog,value=$usermode
        flowop read name=shadowread-ware_0_0,filename=ware_0_0,
                iosize=$iosize,workingset=10g,random,dsync,directio
        flowop hog name=shadowhog,value=$usermode
        flowop read name=shadowread-log_1_1,filename=log_1_1,
                iosize=$iosize,workingset=10g,random,dsync,directio
        flowop hog name=shadowhog,value=$usermode
	flowop sempost name=shadow-post-lg,value=1,target=lg-block,blocking
	flowop sempost name=shadow-post-dbwr,value=1,target=dbwr-block,blocking
	flowop eventlimit name=random-rate
  }
}

echo "Tpcso Version 2.1 personality successfully loaded"
usage "Usage: set \$dir=<dir>         defaults to $dir"
usage " "
usage "       set \$eventrate=<value> defaults to $eventrate"
usage " "
usage "       set \$iosize=<value>    defaults to $iosize, typically 2k or 8k"
usage " "
usage "       set \$memperthread=<value> defaults to $memperthread, there are 211 threads"
usage " "
usage "       run runtime (e.g. run 60)"
usage " "
usage "Note - this workload needs at least 512MB of of memory"
usage " "
