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
 * Intel model-specific support.  Right now all this conists of is
 * to modify the ereport subclass to produce different ereport classes
 * so that we can have different diagnosis rules and corresponding faults.
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/modctl.h>
#include <sys/mca_x86.h>
#include <sys/cpu_module_ms_impl.h>
#include <sys/mc_intel.h>
#include <sys/pci_cfgspace.h>

int gintel_ms_support_disable = 0;
int gintel_error_action_return = 0;
int gintel_ms_unconstrained = 0;

/*ARGSUSED*/
int
gintel_init(cmi_hdl_t hdl, void **datap)
{
	uint32_t nb_chipset;

	if (gintel_ms_support_disable)
		return (ENOTSUP);

	if (!(x86_feature & X86_MCA))
		return (ENOTSUP);

	nb_chipset = (*pci_getl_func)(0, 0, 0, 0x0);
	switch (nb_chipset) {
	case INTEL_NB_7300:
	case INTEL_NB_5000P:
	case INTEL_NB_5000X:
	case INTEL_NB_5000V:
	case INTEL_NB_5000Z:
		if (!gintel_ms_unconstrained)
			gintel_error_action_return |= CMS_ERRSCOPE_POISONED;
		break;
	default:
		break;
	}
	return (0);
}

/*ARGSUSED*/
uint32_t
gintel_error_action(cmi_hdl_t hdl, int ismc, int bank,
    uint64_t status, uint64_t addr, uint64_t misc, void *mslogout)
{
	return (gintel_error_action_return);
}

/*ARGSUSED*/
void
gintel_ereport_class(cmi_hdl_t hdl, cms_cookie_t mscookie,
    const char **cpuclsp, const char **leafclsp)
{
	*cpuclsp = FM_EREPORT_CPU_INTEL;
}

cms_api_ver_t _cms_api_version = CMS_API_VERSION_0;

const cms_ops_t _cms_ops = {
	gintel_init,		/* cms_init */
	NULL,			/* cms_post_startup */
	NULL,			/* cms_post_mpstartup */
	NULL,			/* cms_logout_size */
	NULL,			/* cms_mcgctl_val */
	NULL,			/* cms_bankctl_skipinit */
	NULL,			/* cms_bankctl_val */
	NULL,			/* cms_bankstatus_skipinit */
	NULL,			/* cms_bankstatus_val */
	NULL,			/* cms_mca_init */
	NULL,			/* cms_poll_ownermask */
	NULL,			/* cms_bank_logout */
	gintel_error_action,	/* cms_error_action */
	NULL,			/* cms_disp_match */
	gintel_ereport_class,	/* cms_ereport_class */
	NULL,			/* cms_ereport_detector */
	NULL,			/* cms_ereport_includestack */
	NULL,			/* cms_ereport_add_logout */
	NULL,			/* cms_msrinject */
	NULL,			/* cms_fini */
};

static struct modlcpu modlcpu = {
	&mod_cpuops,
	"Generic Intel model-specific MCA"
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
