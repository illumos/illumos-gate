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
# lib/libbsm/spec/au_open.spec

function	au_close
include		<bsm/libbsm.h>
declaration	int au_close(int d, int keep, short event)
version		SUNW_0.7
errno		
exception	$return == -1
end		

function	au_open
include		<bsm/libbsm.h>
declaration	int au_open(void)
version		SUNW_0.7
errno		
exception	$return == -1
end		

function	au_write
include		<bsm/libbsm.h>
declaration	int au_write(int d, token_t *m)
version		SUNW_0.7
errno		
exception	$return == -1
end		

