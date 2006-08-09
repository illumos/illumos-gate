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
# ucblib/libdbm/spec/dbm.spec

function	delete
include		<dbm.h>
declaration	int delete(datum key)
version		SUNW_1.1
exception	$return < 0
end		

function	firstkey
include		<dbm.h>
declaration	datum firstkey(void)
version		SUNW_1.1
exception	$return.dptr == 0
end		

function	nextkey
include		<dbm.h>
declaration	datum nextkey(datum key)
version		SUNW_1.1
exception	$return.dptr == 0
end		

function	dbminit
include		<dbm.h>
declaration	int dbminit(char *file)
version		SUNW_1.1
exception	$return < 0
end		

function	dbmclose
include		<dbm.h>
declaration	int dbmclose(void)
version		SUNW_1.1
exception	$return < 0
end		

function	fetch
include		<dbm.h>
declaration	datum fetch(datum key)
version		SUNW_1.1
exception	$return.dptr == 0
end		

function	store
include		<dbm.h>
declaration	datum store(datum key, datum dat)
version		SUNW_1.1
exception	$return.dptr == 0
end		

data		bitno
version		SUNW_1.1
end		

data		blkno
version		SUNW_1.1
end		

function	calchash
declaration	long calchash(datum dat)
version		SUNWprivate_1.1
end		

data		dbrdonly
version		SUNW_1.1
end		

data		dirbuf
version		SUNW_1.1
end		

data		dirf
version		SUNW_1.1
end		

function	hashinc
declaration	long hashinc(long h)
version		SUNWprivate_1.1
end		

data		hmask
version		SUNW_1.1
end		

function	makdatum
declaration	datum makdatum(char *s, int l)
version		SUNWprivate_1.1
end		

data		pagbuf
version		SUNW_1.1
end		

data		pagf
version		SUNW_1.1
end		

data		maxbno
version		SUNW_1.1
end		

