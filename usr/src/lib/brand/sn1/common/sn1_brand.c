/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <assert.h>
#include <sn1_brand.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/inttypes.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/brand.h>

extern int errno;

int
sn1_uname(uintptr_t p1)
{
	struct utsname *un = (struct utsname *)p1;
	int rev, err;

	err = syscall(SYS_uname + 1024, p1);
	if (err >= 0) {
		rev = atoi(&un->release[2]);
		assert(rev >= 10);
		(void) sprintf(un->release, "5.%d", rev - 1);
	} else {
		err = -errno;
	}
	return (err);
}

int
sn1_unimpl(uintptr_t p1)
{
	(void) fprintf(stderr,
	    "unimplemented syscall (%d) in emulation library\n", (int)p1);
	return (-EINVAL);
}

#pragma init(sn1_init)

int
sn1_init()
{
	if (syscall(SYS_brand, B_REGISTER, (void *)sn1_handler)) {
		perror("failed to brand the process");
		return (1);
	}

	return (0);
}
