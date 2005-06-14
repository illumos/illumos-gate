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
#	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
#	  All Rights Reserved


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.7	*/

#	Copyright (c) 1984 AT&T
#	  All Rights Reserved


#	Portions Copyright(c) 1988, Sun Microsystems, Inc.
#	All Rights Reserved

# ld command for BSD compatibility package:
#
#       BSD compatibility package libraries (/usr/ucblib) are
#       searched next to third to last.  SVr4 default libraries 
#       (/usr/ccs/lib and /usr/lib) are searched next to last and
#	last respectively.
#
#       Because the BSD compatibility package C library does not 
#       contain all the C library routines of /usr/ccs/lib/libc.a, 
#       the BSD package C library is named /usr/ucblib/libucb.a
#       and is passed explicitly to ld.  This ensures that libucb.a 
#       will be searched first for routines and that 
#       /usr/ccs/lib/libc.a will be searched afterwards for routines 
#       not found in /usr/ucblib/libucb.a.  Also because sockets is    
#       provided in libc under BSD, /usr/lib/libsocket and /usr/lib/nsl
#       are also included as default libraries.
#
#       NOTE: the -Y L, and -Y U, options of ld are not valid 

opts=
LIBS="-lucb -lresolv -lsocket -lnsl -lelf"

if [ $# -eq 0 ]
then
	exit 1
elif [ $# -gt 0 ]
then
	for i in $*
	do
		case $i in
			-r)
				LIBS=""
				opts="$opts $i"
				shift;;
			*)
				opts="$opts $i"
				shift;;
		esac
	done
fi

LD_RUN_PATH=/usr/ucblib /usr/ccs/bin/ld -YP,:/usr/ucblib:/usr/ccs/lib:/usr/lib $opts $LIBS
