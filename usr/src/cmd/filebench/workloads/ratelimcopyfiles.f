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

# RateLimCopyFiles.f uses the iopslimit flowop with the target attribute
# set to the writewholefile flowop to limit the rate to one writewholefile
# operation per event. Without the target attribute set, the limit will
# be one writewholefile OR readwholefile operation per event, so in effect
# it will run at half the rate. Without the target attribute, this workload
# is identical to copyfiles.f. Note that you do have to enable the event
# generator for any of the rate limiting flowops to take effect, for example
# by typing:
#     eventget rate=10
# at the go_filebench prompt to get ten events per second.
#
set $dir=/tmp
set $dirwidth=20
set $filesize=16k
set $iosize=1m
set $nfiles=1000
set $nthreads=1

set mode quit firstdone

define fileset name=bigfileset,path=$dir,size=$filesize,entries=$nfiles,dirwidth=$dirwidth,prealloc=100
define fileset name=destfiles,path=$dir,size=$filesize,entries=$nfiles,dirwidth=$dirwidth

define process name=filereader,instances=1
{
  thread name=filereaderthread,memsize=10m,instances=$nthreads
  {
    flowop openfile name=openfile1,filesetname=bigfileset,fd=1
    flowop readwholefile name=readfile1,fd=1,iosize=$iosize
    flowop createfile name=createfile2,filesetname=destfiles,fd=2
    flowop writewholefile name=writefile2,filesetname=destfiles,fd=2,srcfd=1,iosize=$iosize
    flowop closefile name=closefile1,fd=1
    flowop closefile name=closefile2,fd=2
    flowop iopslimit name=iopslim1, target=writefile2
  }
}

echo  "RateLimCopyFiles Version 1.0 personality successfully loaded"
usage "Usage: set \$dir=<dir>"
usage "       set \$filesize=<size>   defaults to $filesize"
usage "       set \$nfiles=<value>    defaults to $nfiles"
usage "       set \$iosize=<size>     defaults to $iosize"
usage "       set \$dirwidth=<value>  defaults to $dirwidth"
usage "       set \$nthreads=<value>  defaults to $nthreads"
usage " "
usage "       run"
