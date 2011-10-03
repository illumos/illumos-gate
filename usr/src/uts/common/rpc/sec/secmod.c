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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2011 Bayard G. Bell. All rights reserved.
 */

#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/errno.h>

/*
 * Module linkage information for the kernel.
 */

static struct modlmisc modlmisc = {
	&mod_miscops, "kernel RPC security module."
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlmisc,
	NULL
};

extern void sec_subrinit();
extern void sec_subrfini();
extern void svcauthdes_init();
extern void svcauthdes_fini();

int
_init()
{
	int retval = 0;

	sec_subrinit();
	svcauthdes_init();

	if ((retval = mod_install(&modlinkage)) != 0) {
		/*
		 * Failed to load module, cleanup previous
		 * initialization work.
		 */
		sec_subrfini();
		svcauthdes_fini();
	}

	return (retval);
}

int
_fini()
{
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
