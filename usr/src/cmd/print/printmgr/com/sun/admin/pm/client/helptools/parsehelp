#!/bin/ksh
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
# ident	"%Z%%M%	%I%	%E% SMI"
# Copyright (c) 1999, by Sun Microsystems, Inc.
# All rights reserved.
#
# Helper script for processing raw help files.
# Parameters:
#    -D <classpath>  appends <classpath> to $CLASSPATH
#    -J <java_dir>   uses <java_dir>/bin/java.  Default is /usr/java.
#    -V              enable verbose runtime messages


if [[ $# == 0 ]];  then 
	  echo "One or more raw help files must be specified." 
	  echo "Usage:"  
	  echo "    $0 [-D classpath] [-J java_home_dir] [-V] [-C comment_file] [-d destination-file] raw-help-file [raw-help-file]" 
	  exit -1
fi

while getopts "D:J:C:V" opt; do

	case $opt in 
	D) DARG=$OPTARG;;

	J) JARG=$OPTARG;;

	C) COMMENT="-c "$OPTARG;;

	V) VERBOSE="-v";;

	esac
done

shift $(($OPTIND - 1))

#echo "DARG: $DARG JARG: $JARG"
#echo "num left: " $#
#echo "args: $*"

if [[ x$JARG == x ]]; then
	# echo "Using default java"
	JAVA_HOME="/usr/java"
else
	JAVA_HOME=$JARG
fi

DIR=$DARG


#PATH="$JAVA_HOME/bin:/usr/bin:/usr/sbin:/sbin:.:$PATH"
THREADS_FLAG="native"
CLASSPATH=":.:./helptools:$DIR"

# echo "Path: $PATH"
# echo "CLASSPATH: $CLASSPATH"
# echo "Java: $JAVA_HOME/bin/java"

echo "Processing raw help files..."
# $JAVA_HOME/bin/java -fullversion
$JAVA_HOME/bin/java -classpath $CLASSPATH parseMain $COMMENT $VERBOSE $* 

