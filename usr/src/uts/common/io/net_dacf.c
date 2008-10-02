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

/*
 * This module provides the dacf functions to be called after a device
 * of "ddi_network" node type has attached and before it detaches.
 * Specifically, net_postattach() will be called during the post-attach
 * process of each "ddi_network" device, and net_predetach() will be
 * called during the pre-detach process of each device.
 */
#include <sys/modctl.h>
#include <sys/sunddi.h>
#include <sys/ddi.h>
#include <sys/dacf.h>
#include <sys/softmac.h>

/*
 * DACF entry points
 */
static int	net_postattach(dacf_infohdl_t, dacf_arghdl_t, int);
static int	net_predetach(dacf_infohdl_t, dacf_arghdl_t, int);

static dacf_op_t net_config_op[] = {
	{ DACF_OPID_POSTATTACH,	net_postattach	},
	{ DACF_OPID_PREDETACH,	net_predetach	},
	{ DACF_OPID_END,	NULL		},
};

static dacf_opset_t opsets[] = {
	{ "net_config", net_config_op 		},
	{ NULL,		NULL 			}
};

static struct dacfsw dacfsw = {
	DACF_MODREV_1,
	opsets
};

static struct modldacf modldacf = {
	&mod_dacfops,
	"net DACF",
	&dacfsw
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldacf, NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * Post-attach routine invoked for DDI_NT_NET drivers by DACF framework
 */
/* ARGSUSED */
static int
net_postattach(dacf_infohdl_t info_hdl, dacf_arghdl_t arg_hdl, int flags)
{
	dev_info_t	*dip;
	dev_t		dev;
	int		err;

	dip = dacf_devinfo_node(info_hdl);
	dev = dacf_get_dev(info_hdl);

	if ((err = softmac_create(dip, dev)) != 0) {
		const char	*drvname;
		int		ppa;

		drvname = ddi_driver_name(dip);
		ppa = i_ddi_devi_get_ppa(dip);
		cmn_err(CE_WARN, "net_postattach: cannot create softmac "
		    "for device %s%d (%d)", drvname, ppa, err);
		return (DACF_FAILURE);
	}

	return (DACF_SUCCESS);
}

/*
 * Pre-detach routine invoked for DDI_NT_NET drivers by DACF framework
 */
/* ARGSUSED */
static int
net_predetach(dacf_infohdl_t info_hdl, dacf_arghdl_t arg_hdl, int flags)
{
	dev_info_t	*dip;
	dev_t		dev;

	dip = dacf_devinfo_node(info_hdl);
	dev = dacf_get_dev(info_hdl);

	if (softmac_destroy(dip, dev) != 0)
		return (DACF_FAILURE);

	return (DACF_SUCCESS);
}
