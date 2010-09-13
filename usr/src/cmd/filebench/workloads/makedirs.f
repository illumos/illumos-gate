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
# Creates a directory with $ndirs potential leaf directories, than mkdir's them
#
set $dir=/tmp
set $ndirs=10000
set $meandirwidth=100
set $nthreads=16

set mode quit firstdone

define fileset name=bigfileset,path=$dir,size=0,leafdirs=$ndirs,dirwidth=$meandirwidth

define process name=dirmake,instances=1
{
  thread name=dirmaker,memsize=1m,instances=$nthreads
  {
    flowop makedir name=mkdir1,filesetname=bigfileset
  }
}

echo  "MakeDirs Version 1.0 personality successfully loaded"
usage "Usage: set \$dir=<dir>          defaults to $dir"
usage "       set \$meandirwidth=<size> defaults to $meandirwidth"
usage "       set \$ndirs=<value>      defaults to $ndirs"
usage "       set \$nthreads=<value>   defaults to $nthreads"
usage "(sets mean dir width and dir depth is calculated as log (width, ndirs)"
usage " "
usage "       run"
