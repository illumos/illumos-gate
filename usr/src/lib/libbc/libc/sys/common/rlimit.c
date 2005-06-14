/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 1990 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/syscall.h>


/* 
 * The following are the resource values for SVR4.
 * The resource values are mapped to SVR4 values
 * before invoking the system calls.
 */
int rlim_res[RLIM_NLIMITS] = {0, 1, 2, 3, 4, -1, 5};

int getrlimit(resource, rlp)
int resource;
struct rlimit *rlp;
{
	return(bc_getrlimit(resource, rlp));
}

int bc_getrlimit(resource, rlp)
int resource;
struct rlimit *rlp;
{
	return(_syscall(SYS_getrlimit, rlim_res[resource], rlp));
}

int setrlimit(resource, rlp)
int resource;
struct rlimit *rlp;
{
	return(bc_setrlimit(resource, rlp));
}

int bc_setrlimit(resource, rlp)
int resource;
struct rlimit *rlp;
{
	return(_syscall(SYS_setrlimit, rlim_res[resource], rlp));
}
