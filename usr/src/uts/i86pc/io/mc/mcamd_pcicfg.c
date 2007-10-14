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

#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <mcamd_pcicfg.h>
#include <sys/pci_cfgspace.h>

struct _mc_pcicfg_hdl {
	mc_t *cfh_mc;
	enum mc_funcnum cfh_func;
	ddi_acc_handle_t cfh_hdl;
};

static int
mccfgsetup(struct _mc_pcicfg_hdl *hdlp, mc_t *mc, enum mc_funcnum func)
{
	hdlp->cfh_mc = mc;
	hdlp->cfh_func = func;

	if (mc->mc_funcs[func].mcf_devi == NULL)
		return (DDI_FAILURE);

	if (pci_config_setup(mc->mc_funcs[func].mcf_devi, &hdlp->cfh_hdl) !=
	    DDI_SUCCESS)
		return (DDI_FAILURE);

	return (DDI_SUCCESS);
}

int
mc_pcicfg_setup(mc_t *mc, enum mc_funcnum func, mc_pcicfg_hdl_t *cookiep)
{
	struct _mc_pcicfg_hdl *hdlp;

	*cookiep = hdlp = kmem_alloc(sizeof (struct _mc_pcicfg_hdl), KM_SLEEP);

	if (mccfgsetup(hdlp, mc, func) == DDI_FAILURE) {
		kmem_free(hdlp, sizeof (*hdlp));
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

void
mc_pcicfg_teardown(mc_pcicfg_hdl_t cookie)
{
	struct _mc_pcicfg_hdl *hdlp = cookie;

	pci_config_teardown(&hdlp->cfh_hdl);
	kmem_free(hdlp, sizeof (*hdlp));
}

uint32_t
mc_pcicfg_get32(mc_pcicfg_hdl_t cookie, off_t offset)
{
	struct _mc_pcicfg_hdl *hdlp = cookie;

	return (pci_config_get32(hdlp->cfh_hdl, offset));
}

void
mc_pcicfg_put32(mc_pcicfg_hdl_t cookie, off_t offset, uint32_t val)
{
	struct _mc_pcicfg_hdl *hdlp = cookie;

	pci_config_put32(hdlp->cfh_hdl, offset, val);
}

uint32_t
mc_pcicfg_get32_nohdl(mc_t *mc, enum mc_funcnum func, off_t offset)
{
	return ((*pci_getl_func)(0, MC_AMD_DEV_OFFSET + mc->mc_props.mcp_num,
	    func, offset));
}

void
mc_pcicfg_put32_nohdl(mc_t *mc, enum mc_funcnum func, off_t offset,
    uint32_t val)
{
	(*pci_putl_func)(0, MC_AMD_DEV_OFFSET + mc->mc_props.mcp_num,
	    func, offset, val);
}
