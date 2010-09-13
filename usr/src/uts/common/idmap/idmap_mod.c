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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#ifdef	DEBUG
#include <sys/cmn_err.h>
#endif	/* DEBUG */
#include <sys/kidmap.h>
#include "kidmap_priv.h"




extern struct mod_ops mod_miscops;

static struct modlmisc misc =
{
	&mod_miscops,
	"ID Mapping kernel module"
};

static struct modlinkage linkage =
{
	MODREV_1,
	(void *) &misc,
	NULL
};


int
_init()
{
	int i;

	if ((i =  mod_install(&linkage)) != 0) {
#ifdef	DEBUG
		cmn_err(CE_WARN, "idmap: Failed to load kernel module");
#endif	/* DEBUG */
		return (i);
	}

	if (kidmap_start() != 0) {
#ifdef	DEBUG
		cmn_err(CE_WARN, "idmap: Failed to start");
#endif	/* DEBUG */
		return (i);
	}

	return (i);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&linkage, modinfop));
}

int
_fini()
{
	int i;

	if ((i = kidmap_stop()) != 0) {
		return (i);
	}

	if ((i = mod_remove(&linkage)) != 0) {
#ifdef	DEBUG
		cmn_err(CE_WARN, "idmap: Failed to remove kernel module");
#endif	/* DEBUG */
		return (i);
	}

	return (0);
}
