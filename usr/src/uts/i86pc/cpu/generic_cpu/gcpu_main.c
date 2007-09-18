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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Generic x86 CPU Module
 *
 * This CPU module is used for generic x86 CPUs when Solaris has no other
 * CPU-specific support module available.  Code in this module should be the
 * absolute bare-bones support and must be cognizant of both Intel and AMD etc.
 */

#include <sys/types.h>
#include <sys/cpu_module_impl.h>
#include <sys/cpuvar.h>
#include <sys/kmem.h>
#include <sys/modctl.h>

#include "gcpu.h"

/*ARGSUSED*/
static void
gcpu_nop(void *data)
{
}

static int
gcpu_notsup(void)
{
	return (ENOTSUP);
}

static int
gcpu_nil(void)
{
	return (0);
}

static void *
gcpu_null(void)
{
	return (NULL);
}

/*ARGSUSED*/
static int
gcpu_init(cpu_t *cpu, void **datap)
{
	*datap = kmem_zalloc(sizeof (gcpu_data_t), KM_SLEEP);
	return (0);
}

static void
gcpu_fini(void *data)
{
	gcpu_data_t *dp = data;

	kmem_free(dp->gcpu_mca.gcpu_mca_data,
	    dp->gcpu_mca.gcpu_mca_nbanks * sizeof (gcpu_mca_data_t));

	kmem_free(dp, sizeof (gcpu_data_t));
}

const cmi_ops_t _cmi_ops = {
	gcpu_init,		/* cmi_init */
	gcpu_nop,		/* cmi_post_init */
	gcpu_nop,		/* cmi_post_mpstartup */
	gcpu_fini,		/* cmi_fini */
	gcpu_nop,		/* cmi_faulted_enter */
	gcpu_nop,		/* cmi_faulted_exit */
	(int (*)())gcpu_nil,	/* cmi_scrubber_enable */
	gcpu_mca_init,		/* cmi_mca_init */
	gcpu_mca_trap,		/* cmi_mca_trap */
	(int (*)())gcpu_notsup,	/* cmi_mca_inject */
	gcpu_nop,		/* cmi_mca_poke */
	(void (*)())gcpu_nop,			/* cmi_mc_register */
	(const cmi_mc_ops_t *(*)())gcpu_null	/* cmi_mc_getops */
};

static struct modlcpu modlcpu = {
	&mod_cpuops,
	"Generic x86 CPU Module"
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlcpu,
	NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}
