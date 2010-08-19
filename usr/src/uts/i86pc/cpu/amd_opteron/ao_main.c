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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * The CPU module for the AMD Athlon64 and Opteron processors
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/sunddi.h>
#include <sys/cpu_module.h>
#include <sys/cpu_module_ms_impl.h>
#include <sys/cpuvar.h>
#include <sys/x86_archext.h>
#include <sys/kmem.h>
#include <sys/pghw.h>
#include <sys/modctl.h>
#include <sys/mc.h>
#include <sys/mca_x86.h>

#include "ao.h"

int ao_ms_support_disable = 0;

static struct ao_chipshared *ao_shared[AO_MAX_CHIPS];

/*
 * This cpu module supports AMD family 0xf revisions B/C/D/E/F/G.  If
 * a family 0xf cpu beyond the rev G model limit is detected then
 * return ENOTSUP and let the generic x86 CPU module load instead.
 */
uint_t ao_model_limit = 0x6f;

int
ao_ms_init(cmi_hdl_t hdl, void **datap)
{
	uint_t chipid = cmi_hdl_chipid(hdl);
	struct ao_chipshared *sp, *osp;
	ao_ms_data_t *ao;
	uint64_t cap;

	if (ao_ms_support_disable || cmi_hdl_model(hdl) >= ao_model_limit)
		return (ENOTSUP);

	if (!is_x86_feature(x86_featureset, X86FSET_MCA))
		return (ENOTSUP);

	if (cmi_hdl_rdmsr(hdl, IA32_MSR_MCG_CAP, &cap) != CMI_SUCCESS)
		return (ENOTSUP);

	if (!(cap & MCG_CAP_CTL_P))
		return (ENOTSUP);

	if ((cap & MCG_CAP_COUNT_MASK) != AMD_MCA_BANK_COUNT) {
		cmn_err(CE_WARN, "Chip %d core %d has %llu MCA banks, "
		    "expected %u: disabling AMD-specific MCA support on "
		    "this CPU", chipid, cmi_hdl_coreid(hdl),
		    (u_longlong_t)cap & MCG_CAP_COUNT_MASK,
		    AMD_MCA_BANK_COUNT);
		return (ENOTSUP);
	}

	ao = *datap = kmem_zalloc(sizeof (ao_ms_data_t), KM_SLEEP);
	cmi_hdl_hold(hdl);	/* release in fini */
	ao->ao_ms_hdl = hdl;

	/*
	 * Allocate the chipshared structure if it appears not to have been
	 * allocated already (by a sibling core).  Install the newly
	 * allocated pointer atomically in case a sibling core beats
	 * us to it.
	 */
	if ((sp = ao_shared[chipid]) == NULL) {
		sp = kmem_zalloc(sizeof (struct ao_chipshared), KM_SLEEP);
		sp->aos_chiprev = cmi_hdl_chiprev(hdl);
		membar_producer();

		osp = atomic_cas_ptr(&ao_shared[chipid], NULL, sp);
		if (osp != NULL) {
			kmem_free(sp, sizeof (struct ao_chipshared));
			sp = osp;
		}
	}
	ao->ao_ms_shared = sp;

	return (0);
}

/*ARGSUSED*/
void
ao_ms_post_mpstartup(cmi_hdl_t hdl)
{
	(void) ddi_install_driver("mc-amd");
}

cms_api_ver_t _cms_api_version = CMS_API_VERSION_2;

const cms_ops_t _cms_ops = {
	ao_ms_init,			/* cms_init */
	ao_ms_post_startup,		/* cms_post_startup */
	ao_ms_post_mpstartup,		/* cms_post_mpstartup */
	NULL,				/* cms_logout_size */
	ao_ms_mcgctl_val,		/* cms_mcgctl_val */
	ao_ms_bankctl_skipinit,		/* cms_bankctl_skipinit */
	ao_ms_bankctl_val,		/* cms_bankctl_val */
	NULL,				/* cms_bankstatus_skipinit */
	NULL,				/* cms_bankstatus_val */
	ao_ms_mca_init,			/* cms_mca_init */
	ao_ms_poll_ownermask,		/* cms_poll_ownermask */
	NULL,				/* cms_bank_logout */
	ao_ms_error_action,		/* cms_error_action */
	ao_ms_disp_match,		/* cms_disp_match */
	ao_ms_ereport_class,		/* cms_ereport_class */
	NULL,				/* cms_ereport_detector */
	ao_ms_ereport_includestack,	/* cms_ereport_includestack */
	ao_ms_ereport_add_logout,	/* cms_ereport_add_logout */
	ao_ms_msrinject,		/* cms_msrinject */
	NULL,				/* cms_fini */
};

static struct modlcpu modlcpu = {
	&mod_cpuops,
	"AMD Athlon64/Opteron Model-Specific Support"
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
