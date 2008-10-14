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

#define	_SPUNI_

#include <sys/types.h>
#include <sys/ksynch.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/modctl.h>
#include <sys/cred.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/unistat/spcs_s.h>

#ifdef DS_DDICT
#include <sys/nsctl/contract.h>
#endif

#include <sys/nsctl/nsctl.h>
#include <sys/nsctl/nsvers.h>

/*
 * Module linkage.
 */

static struct modlmisc spuni_modlmisc = {
	&mod_miscops,	/* Type of module */
	"nws:Unistat:" ISS_VERSION_STR
};

static struct modlinkage spuni_modlinkage = {
	MODREV_1,
	&spuni_modlmisc,
	NULL
};

int
_init(void)
{
#ifdef DEBUG
	cmn_err(CE_NOTE, "spuni: initializing Storage Product Unistat v1.01");
#endif
	return (mod_install(&spuni_modlinkage));
}

int
_fini(void)
{
#ifdef DEBUG
	cmn_err(CE_NOTE, "spuni: unloading Storage Product Unistat v1.01");
#endif
	return (mod_remove(&spuni_modlinkage));
}

/*
 * 	Solaris module info code
 */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&spuni_modlinkage, modinfop));
}
