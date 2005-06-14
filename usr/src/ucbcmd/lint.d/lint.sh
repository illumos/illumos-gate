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
# Copyright 1989 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
#	  All Rights Reserved

# University Copyright- Copyright (c) 1982, 1986, 1988
# The Regents of the University of California
# All Rights Reserved
#
# University Acknowledgment- Portions of this document are derived from
# software developed by the University of California, Berkeley, and its
# contributors.

#pragma ident	"%Z%%M%	%I%	%E% SMI"


# lint command for BSD compatibility package:
#
#	BSD compatibility package header files (/usr/ucbinclude)
#	are included before SVr4 default (/usr/include) files but 
#       after any directories specified on the command line via 
#	the -I option.  Thus, the BSD header files are included
#	next to last, and SVr4 header files are searched last.
#	
#	BSD compatibility package libraries are searched first.
#
#	Because the BSD compatibility package C lint library does not 
#	contain all the C library routines of /usr/ccs/lib/llib-lc, 
#	the BSD package C library is named /usr/ucblib/llib-lucb
#	and is passed explicitly to lint.  This ensures that llib-lucb
#	will be searched first for routines and that 
#	/usr/ccs/lib/llib-lc will be searched afterwards for routines 
#	not found in /usr/ucblib/llib-lucb.  Also because sockets is    
#       provided in libc under BSD, /usr/lib/llib-lsocket and 
#	/usr/lib/llib-lnsl are also included as default libraries.
#	
#	Note: Lint does not allow you to reset the search PATH for
# 	libraries. The following uses the -L option to point to
#	/usr/ucblib. There are however some combinations of options
#	specified by the user that could overrule the intended path.
#

if [ -f /usr/ccs/bin/ucblint ]
then
	/usr/ccs/bin/ucblint -L/usr/ucblib -Xs "$@" -I/usr/ucbinclude \
	-L/usr/ucblib -lucb -lsocket -lnsl -lelf
	ret=$?
	exit $ret
else
	echo "/usr/ucb/lint:  language optional software not installed"
	exit 1
fi
