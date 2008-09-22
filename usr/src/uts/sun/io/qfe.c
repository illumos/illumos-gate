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
 * SunOS MT QFE Device Driver (layered above FEPS/Cheerio)
 */

#include	<sys/types.h>
#include	<sys/debug.h>
#include	<sys/stream.h>
#include	<sys/cmn_err.h>
#include	<sys/kmem.h>
#include	<sys/modctl.h>
#include	<sys/conf.h>
#include	<sys/mac.h>
#include	<sys/mac_ether.h>
#include	<sys/ddi.h>
#include	<sys/sunddi.h>

/*
 * Function prototypes.
 */
extern int hmeattach(dev_info_t *, ddi_attach_cmd_t);
extern int hmedetach(dev_info_t *, ddi_detach_cmd_t);

DDI_DEFINE_STREAM_OPS(qfe_dev_ops, nulldev, nulldev, hmeattach, hmedetach,
    nodev, NULL, D_MP, NULL, ddi_quiesce_not_supported);

/*
 * Module linkage information for the kernel.
 */
static struct modldrv modldrv = {
	&mod_driverops,	/* Type of module.  This one is a driver */
	"Sun QFE 10/100 Mb Ethernet",
	&qfe_dev_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};

/* <<<<<<<<<<<<<<<<<<<<<<<<<<<  LOADABLE ENTRIES  >>>>>>>>>>>>>>>>>>>>>>> */

int
_init(void)
{
	int	status;

	mac_init_ops(&qfe_dev_ops, "qfe");
	if ((status = mod_install(&modlinkage)) != 0) {
		mac_fini_ops(&qfe_dev_ops);
	}
	return (status);
}

int
_fini(void)
{
	int	status;

	if ((status = mod_remove(&modlinkage)) == 0) {
		mac_fini_ops(&qfe_dev_ops);
	}
	return (status);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
