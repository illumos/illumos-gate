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

/*
 * The CPU module for the AMD Athlon64 and Opteron processors
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/sunddi.h>
#include <sys/cpu_module_impl.h>
#include <sys/cpuvar.h>
#include <sys/x86_archext.h>
#include <sys/kmem.h>
#include <sys/modctl.h>
#include <sys/mc.h>
#include <sys/mca_x86.h>

#include "ao.h"

/*
 * At present this CPU module only supports the features for Athlon64 and
 * Opteron up to and including the Rev E processor.  If we detect Rev F or
 * later, return ENOTSUP and let the generic x86 CPU module load instead.
 * Opteron Rev F is currently defined as Family 0xF Model [0x40 .. 0x5F].
 */
uint_t ao_model_limit = 0x40;

static int
ao_init(cpu_t *cp, void **datap)
{
	ao_data_t *ao;
	uint64_t cap;

	if (cpuid_getmodel(cp) >= ao_model_limit)
		return (ENOTSUP);

	if (!(x86_feature & X86_MCA))
		return (ENOTSUP);

	cap = rdmsr(IA32_MSR_MCG_CAP);
	if (!(cap & MCG_CAP_CTL_P))
		return (ENOTSUP);

	ao = *datap = kmem_zalloc(sizeof (ao_data_t), KM_SLEEP);
	ao->ao_cpu = cp;

	return (0);
}

/*ARGSUSED*/
static void
ao_post_mpstartup(void *data)
{
	(void) ddi_install_driver("mc-amd");
}

static void
ao_fini(void *data)
{
	kmem_free(data, sizeof (ao_data_t));
}

const cmi_ops_t _cmi_ops = {
	ao_init,
	ao_mca_post_init,
	ao_post_mpstartup,
	ao_fini,
	ao_faulted_enter,
	ao_faulted_exit,
	ao_scrubber_enable,
	ao_mca_init,
	ao_mca_trap,
	ao_mca_inject,
	ao_mca_poke,
	ao_mc_register,
	ao_mc_getops
};

static struct modlcpu modlcpu = {
	&mod_cpuops,
	"AMD Athlon64/Opteron CPU Module"
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlcpu,
	NULL
};

int
_init(void)
{
	int err;

	ao_mca_queue = errorq_create("ao_mca_queue",
	    ao_mca_drain, NULL, AO_MCA_MAX_ERRORS * (max_ncpus + 1),
	    sizeof (ao_cpu_logout_t), 1, ERRORQ_VITAL);

	if (ao_mca_queue == NULL)
		return (EAGAIN); /* errorq_create() logs a message for us */

	if ((err = mod_install(&modlinkage)) != 0) {
		errorq_destroy(ao_mca_queue);
		ao_mca_queue = NULL;
	}

	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int err;

	if ((err = mod_remove(&modlinkage)) == 0)
		errorq_destroy(ao_mca_queue);

	return (err);
}
