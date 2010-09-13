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

# Create a fileset of 50,000 entries ($nfiles), where each file's size is set
# via a gamma distribution with the median size of 16KB ($filesize).
# Fire off 16 threads ($nthreads), where each thread stops after
# deleting 1000 ($count) files.

set $dir=/tmp
set $count=1000
set $filesize=16k
set $nfiles=5000
set $meandirwidth=100
set $nthreads=16

set mode quit firstdone

define fileset name=bigfileset,path=$dir,size=$filesize,entries=$nfiles,dirwidth=$meandirwidth,prealloc=100,paralloc

define process name=filedelete,instances=1
{
  thread name=filedeletethread,memsize=10m,instances=$nthreads
  {
    flowop deletefile name=deletefile1,filesetname=bigfileset
    flowop opslimit name=limit
    flowop finishoncount name=finish,value=$count
  }
}

echo  "FileMicro-Delete Version 2.4 personality successfully loaded"
usage "Usage: set \$dir=<dir>           defaults to $dir"
usage "       set \$count=<value>       defaults to $count"
usage "       set \$filesize=<size>     defaults to $filesize"
usage "       set \$nfiles=<value>      defaults to $nfiles"
usage "       set \$meandirwidth=<size> defaults to $meandirwidth"
usage "       set \$nthreads=<value>    defaults to $nthreads"
usage "(sets mean dir width and dir depth is calculated as log (width, nfiles)"
usage " "
usage "       run"

