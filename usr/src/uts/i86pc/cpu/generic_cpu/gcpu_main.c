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
 * Copyright (c) 2018, Joyent, Inc.
 */
/*
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 */

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
#include <sys/pghw.h>

#include "gcpu.h"

/*
 * Prevent generic cpu support from loading.
 */
int gcpu_disable = 0;

#define	GCPU_MAX_CHIPID		32
static struct gcpu_chipshared *gcpu_shared[GCPU_MAX_CHIPID];

/*
 * Our cmi_init entry point, called during startup of each cpu instance.
 */
int
gcpu_init(cmi_hdl_t hdl, void **datap)
{
	uint_t chipid = cmi_hdl_chipid(hdl);
	struct gcpu_chipshared *sp, *osp;
	gcpu_data_t *gcpu;

	if (gcpu_disable || chipid >= GCPU_MAX_CHIPID)
		return (ENOTSUP);

	/*
	 * Allocate the state structure for this cpu.  We will only
	 * allocate the bank logout areas in gcpu_mca_init once we
	 * know how many banks there are.
	 */
	gcpu = *datap = kmem_zalloc(sizeof (gcpu_data_t), KM_SLEEP);
	cmi_hdl_hold(hdl);	/* release in gcpu_fini */
	gcpu->gcpu_hdl = hdl;

	/*
	 * Allocate a chipshared structure if no sibling cpu has already
	 * allocated it, but allow for the fact that a sibling core may
	 * be starting up in parallel.
	 */
	if ((sp = gcpu_shared[chipid]) == NULL) {
		sp = kmem_zalloc(sizeof (struct gcpu_chipshared), KM_SLEEP);
		mutex_init(&sp->gcpus_poll_lock, NULL, MUTEX_DRIVER, NULL);
		mutex_init(&sp->gcpus_cfglock, NULL, MUTEX_DRIVER, NULL);
		osp = atomic_cas_ptr(&gcpu_shared[chipid], NULL, sp);
		if (osp != NULL) {
			mutex_destroy(&sp->gcpus_cfglock);
			mutex_destroy(&sp->gcpus_poll_lock);
			kmem_free(sp, sizeof (struct gcpu_chipshared));
			sp = osp;
		}
	}

	atomic_inc_32(&sp->gcpus_actv_cnt);
	gcpu->gcpu_shared = sp;

	return (0);
}

/*
 * deconfigure gcpu_init()
 */
void
gcpu_fini(cmi_hdl_t hdl)
{
	uint_t chipid = cmi_hdl_chipid(hdl);
	gcpu_data_t *gcpu = cmi_hdl_getcmidata(hdl);
	struct gcpu_chipshared *sp;

	if (gcpu_disable || chipid >= GCPU_MAX_CHIPID)
		return;

	gcpu_mca_fini(hdl);

	/*
	 * Keep shared data in cache for reuse.
	 */
	sp = gcpu_shared[chipid];
	ASSERT(sp != NULL);
	atomic_dec_32(&sp->gcpus_actv_cnt);

	if (gcpu != NULL)
		kmem_free(gcpu, sizeof (gcpu_data_t));

	/* Release reference count held in gcpu_init(). */
	cmi_hdl_rele(hdl);
}

void
gcpu_post_startup(cmi_hdl_t hdl)
{
	gcpu_data_t *gcpu = cmi_hdl_getcmidata(hdl);

	if (gcpu_disable)
		return;

	if (gcpu != NULL)
		cms_post_startup(hdl);
#ifdef __xpv
	/*
	 * All cpu handles are initialized so we can begin polling now.
	 * Furthermore, our virq mechanism requires that everything
	 * be run on cpu 0 so we can assure that by starting from here.
	 */
	gcpu_mca_poll_start(hdl);
#else
	/*
	 * The boot CPU has a bit of a chicken and egg problem for CMCI. Its MCA
	 * initialization is run before we have initialized the PSM module that
	 * we would use for enabling CMCI. Therefore, we use this as a chance to
	 * enable CMCI for the boot CPU. For all other CPUs, this chicken and
	 * egg problem will have already been solved.
	 */
	gcpu_mca_cmci_enable(hdl);
#endif
}

void
gcpu_post_mpstartup(cmi_hdl_t hdl)
{
	if (gcpu_disable)
		return;

	cms_post_mpstartup(hdl);

#ifndef __xpv
		/*
		 * All cpu handles are initialized only once all cpus
		 * are started, so we can begin polling post mp startup.
		 */
		gcpu_mca_poll_start(hdl);
#endif
}

#ifdef __xpv
#define	GCPU_OP(ntvop, xpvop)	xpvop
#else
#define	GCPU_OP(ntvop, xpvop)	ntvop
#endif

cmi_api_ver_t _cmi_api_version = CMI_API_VERSION_3;

const cmi_ops_t _cmi_ops = {
	gcpu_init,				/* cmi_init */
	gcpu_post_startup,			/* cmi_post_startup */
	gcpu_post_mpstartup,			/* cmi_post_mpstartup */
	gcpu_faulted_enter,			/* cmi_faulted_enter */
	gcpu_faulted_exit,			/* cmi_faulted_exit */
	gcpu_mca_init,				/* cmi_mca_init */
	GCPU_OP(gcpu_mca_trap, NULL),		/* cmi_mca_trap */
	GCPU_OP(gcpu_cmci_trap, NULL),		/* cmi_cmci_trap */
	gcpu_msrinject,				/* cmi_msrinject */
	GCPU_OP(gcpu_hdl_poke, NULL),		/* cmi_hdl_poke */
	gcpu_fini,				/* cmi_fini */
	GCPU_OP(NULL, gcpu_xpv_panic_callback),	/* cmi_panic_callback */
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
