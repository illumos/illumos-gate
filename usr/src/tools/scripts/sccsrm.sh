#!/usr/bin/sh 
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright (c) 1993-1998 by Sun Microsystems, Inc.
# All rights reserved.
# 
#ident	"%Z%%M%	%I%	%E% SMI"
#
#	This script is to be used to remove files from any CodeManager
#	workspace.  It will do this by moving the specified file,
#	and its corresponding s-dot file, to a .del-<file>-`date`
# 	format.
#
#	The only way to remove files under the CodeManager is
#	through the rename mechanism - it is not enough to
#	simply 'rm' the file.
#

USAGE="usage: sccsrm [-f] <filename> ..."

message() {
   if [ ${F_FLAG} -eq 0 ]; then
      echo "$*"
   fi
} 

#
# LC_ALL=C is set so that the this script will work no matter
# which localization you have installed on your machine.  Some
# localizations can cause the output of 'date' and other commands
# to vary.
#
LC_ALL="C"; export LC_ALL

date=`/usr/bin/date +%h-%d-%y`
F_FLAG=0


#
# Parse options...
#
set -- `getopt f $*`
if [ $? != 0 ]; then
   echo $USAGE
   exit 2
fi


for i in $*
do
   case $i in
   -f) F_FLAG=1; shift;;
   --) shift; break;;
   esac
done

if [ $# -eq 0 ]; then
   message $USAGE   
   exit 1
fi

#
# Process s-dot files.
#
for file in $*
do
   new_file="${file}-${date}"
   #
   # if there is a deleted file of the same name we then append the pid
   # to the name.
   if [ -f SCCS/s..del-${new_file} -o -d .del-${new_file} ]; then
      new_file="${new_file}.$$"
   fi
   if [ -f SCCS/s.$file ]; then
      if [ -f SCCS/p.${file} ]; then
         if [ ${F_FLAG} -eq 0 ]; then
	    echo "warning: ${file} is checked out for editing, all edits will be lost - continue (y/n)"
	    read ans
	    while [ `expr $ans : "^[YyNn]"` -eq 0 ]
	    do
	       echo "warning: ${file} is checked out for editing, all edits will be lost - continue (y/n)"
	       read ans
	    done
	 else
	    ans="y"
	 fi
	 if [ `expr $ans : "^[Yy]"` -eq 1 ]; then
            rm -f SCCS/p.${file}
	    rm -f ${file}
	 else
	    continue
	 fi
      fi
      if [ -f ${file} ]; then
         mv ${file} .del-${new_file}
      fi
      mv SCCS/s.${file} SCCS/s..del-${new_file}
   elif [ -d ${file} -a ${file} != "SCCS" ]; then
      mv ${file} .del-${new_file}
   else
      message "${file}: not an SCCS file"
   fi
done



