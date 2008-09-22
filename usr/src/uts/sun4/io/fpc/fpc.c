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


#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <fpc.h>

static int fpc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int fpc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

static struct dev_ops fpc_ops = {
	DEVO_REV,
	0,
	nulldev,
	nulldev,
	nulldev,
	fpc_attach,
	fpc_detach,
	nodev,
	NULL,
	NULL,
	nodev,
	ddi_quiesce_not_needed,		/* quiesce */
};

extern struct mod_ops mod_driverops;

static struct modldrv md = {
	&mod_driverops,
	"IO Chip Perf Counter",
	&fpc_ops,
};

static struct modlinkage ml = {
	MODREV_1,
	(void *)&md,
	NULL
};

int
_init(void)
{
	if (fpc_init_platform_check() != SUCCESS)
		return (ENODEV);
	return (mod_install(&ml));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ml, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&ml));
}

static int
fpc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	/*
	 * Since the driver saves no state between calls, we can fully detach
	 * on suspend and fully attach on resume.
	 *
	 * An RFE might be to save event register states for restore.
	 * The result of not doing this is that the kstat reader (busstat)
	 * may quit upon resume, seeing that the events have changed out from
	 * underneath it (since the registers were powered off upon suspend).
	 */
	case DDI_RESUME:
	case DDI_ATTACH:
		if (fpc_kstat_init(dip) != DDI_SUCCESS) {
			(void) fpc_detach(dip, DDI_DETACH);
			return (DDI_FAILURE);
		}
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

static int
fpc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_SUSPEND:
	case DDI_DETACH:
		fpc_kstat_fini(dip);
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}
