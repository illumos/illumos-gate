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

# Sequential write() of a 1G file, size picked from a gamma distribution
# min of 1k and a mean of 5.5K, followed by close(), cached.



set $dir=/tmp
set $nthreads=1
set $cached=false
set $sync=false
set $count=128k

define randvar name=$iosize, type=gamma, min=1k, mean=5632, gamma=1500

define fileset name=bigfileset,path=$dir,size=0,entries=$nthreads,dirwidth=1024,prealloc=100,cached=$cached

define process name=filewriter,instances=1
{
  thread name=filewriterthread,memsize=10m,instances=$nthreads
  {
    flowop openfile name=open-file,filesetname=bigfileset,fd=1
    flowop appendfile name=write-file,dsync=$sync,iosize=$iosize,fd=1,iters=$count
    flowop closefile name=close,fd=1
    flowop finishoncount name=finish,value=1
  }
}

echo  "FileMicro-SeqWriteRandVarGam Version 1.1 personality successfully loaded"
usage "Usage: set \$dir=<dir>"
usage "       set \$cached=<bool>        defaults to $cached"
usage "       set \$count=<value>        defaults to $count"
usage "       set \$iosize.type=<type>   defaults to $iosize.type"
usage "       set \$iosize.randsrc=<src> defaults to $iosize.randsrc"
usage "       set \$iosize.mean=<mean>   defaults to $iosize.mean"
usage "       set \$iosize.gamma=<gamma> defaults to $iosize.gamma"
usage "       set \$nthreads=<value>     defaults to $nthreads"
usage "       set \$sync=<bool>          defaults to $sync"
usage " "
usage "       run runtime (e.g. run 60)"
