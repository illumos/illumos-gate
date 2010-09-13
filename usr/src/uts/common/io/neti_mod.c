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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/param.h>
#include <sys/modctl.h>
#include <sys/neti.h>


/*
 * Module linkage information for the kernel.
 */
static struct modldrv modlmisc = {
	&mod_miscops,		/* drv_modops */
	"netinfo module",	/* drv_linkinfo */
};

static struct modlinkage modlinkage = {
	MODREV_1,		/* ml_rev */
	&modlmisc,		/* ml_linkage */
	NULL
};

/*
 * Module entry points.
 */
int
_init(void)
{
	int error;

	neti_init();
	error = mod_install(&modlinkage);
	if (error != 0)
		neti_fini();

	return (error);
}


int
_fini(void)
{
	int error;

	error = mod_remove(&modlinkage);
	if (error == 0)
		neti_fini();

	return (error);
}


int
_info(struct modinfo *modinfop)
{

	return (mod_info(&modlinkage, modinfop));
}
