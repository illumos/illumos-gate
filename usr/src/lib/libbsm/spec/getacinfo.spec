#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
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
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libbsm/spec/getacinfo.spec

function	getacdir
include		<bsm/libbsm.h>
declaration	int getacdir( char	*dir, int len)
version		SUNW_0.7
errno		
exception	($return == -1 || $return == -2 || $return == -3 )
end		

function	getacmin
include		<bsm/libbsm.h>
declaration	int getacmin( int *min_val)
version		SUNW_0.7
errno		
exception	($return == -2 || $return == -3 )
end		

function	getacflg
include		<bsm/libbsm.h>
declaration	int getacflg( char	*auditstring, int len)
version		SUNW_0.7
errno		
exception	($return == -2 || $return == -3 )
end		

function	getacna
include		<bsm/libbsm.h>
declaration	int getacna( char *auditstring, int len)
version		SUNW_0.7
errno		
exception	($return == -2 || $return == -3 )
end		

function	setac
include		<bsm/libbsm.h>
declaration	void setac( void)
version		SUNW_0.7
errno		
end		

function	endac
include		<bsm/libbsm.h>
declaration	void endac( void)
version		SUNW_0.7
errno		
end		

