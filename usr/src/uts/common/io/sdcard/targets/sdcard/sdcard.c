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
 * SD memory card target driver.  It relies on the SDA common
 * framework, and translates to SCSA.  That is to say, it emulates a
 * simple SCSI block device.
 *
 * The entire driver is a tiny shim for the SDA framework, because to
 * make life simplify and reduce layering overhead, we just use implementation
 * in the SDA framework.
 *
 * (We have to be a separate driver, unfortunately, because SDA nexus drivers
 * need to support SDIO and memory targets, and there can only be one bus_ops
 * per driver.)
 */

#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>


/* our entire API with SDA is miniscule */
extern void sda_mem_init(struct modlinkage *);
extern void sda_mem_fini(struct modlinkage *);

static struct dev_ops sdcard_devops = {
	DEVO_REV,
	0,
	NULL,
	nulldev,
	nulldev,
	NULL,
	NULL,
	nodev,
	NULL,	/* cb_ops */
	NULL,	/* bus_ops */
	NULL,	/* power */
	NULL,	/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"SD Memory Slot",
	&sdcard_devops,
};

static struct modlinkage modlinkage = {
	MODREV_1, { &modldrv, NULL }
};

int
_init(void)
{
	int	rv;

	sda_mem_init(&modlinkage);

	if ((rv = mod_install(&modlinkage)) != 0) {
		sda_mem_fini(&modlinkage);
		return (rv);
	}
	return (rv);
}

int
_fini(void)
{
	int	rv;

	if ((rv = mod_remove(&modlinkage)) == 0) {
		sda_mem_fini(&modlinkage);
		return (rv);
	}
	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
