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
 * sppptun_mod.c - modload support for PPP multiplexing tunnel driver.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/time.h>
#include <sys/conf.h>
#include <sys/kstat.h>
#include <sys/sunddi.h>
#include <net/sppptun.h>
#include <netinet/in.h>

#include "sppptun_mod.h"

/*
 * Descriptions for flags values in cb_flags field:
 *
 * D_MTQPAIR:
 *    An inner perimeter that spans the queue pair.
 * D_MTOUTPERIM:
 *    An outer perimeter that spans over all queues in the module.
 * D_MTOCEXCL:
 *    Open & close procedures are entered exclusively at outer perimeter.
 * D_MTPUTSHARED:
 *    Entry to put procedures are done with SHARED (reader) acess
 *    and not EXCLUSIVE (writer) access.
 *
 * Therefore:
 *
 * 1. Open and close procedures are entered with EXCLUSIVE (writer)
 *    access at the inner perimeter, and with EXCLUSIVE (writer) access at
 *    the outer perimeter.
 *
 * 2. Put procedures are entered with SHARED (reader) access at the inner
 *    perimeter, and with SHARED (reader) access at the outer perimeter.
 *
 * 3. Service procedures are entered with EXCLUSIVE (writer) access at
 *    the inner perimeter, and with SHARED (reader) access at the
 *    outer perimeter.
 *
 * Do not attempt to modify these flags unless the entire corresponding
 * driver code is changed to accomodate the newly represented MT-STREAMS
 * flags. Doing so without making proper modifications to the driver code
 * will severely impact the intended driver behavior, and thus may affect
 * the system's stability and performance.
 */

static int	tun_attach(dev_info_t *, ddi_attach_cmd_t);
static int	tun_detach(dev_info_t *, ddi_detach_cmd_t);
static int	tun_info(dev_info_t *, ddi_info_cmd_t, void *, void **);

static dev_info_t *tun_dev_info;

DDI_DEFINE_STREAM_OPS(sppptun_ops,			\
	nulldev, nulldev,				\
	tun_attach, tun_detach, nodev, tun_info,	\
	D_NEW | D_MP | D_MTQPAIR | D_MTOUTPERIM | D_MTOCEXCL | D_MTPUTSHARED, \
	&sppptun_tab, ddi_quiesce_not_supported);

/*
 * This is the loadable module wrapper.
 */
#include <sys/modctl.h>

/*
 * Module linkage information for the kernel.
 */
static struct fmodsw sppptun_fmodsw = {
	PPP_TUN_NAME,
	&sppptun_tab,
	D_NEW | D_MP | D_MTQPAIR | D_MTOUTPERIM | D_MTOCEXCL | D_MTPUTSHARED
};

static struct modldrv modldrv = {
	&mod_driverops,
	(char *)sppptun_driver_description,
	&sppptun_ops
};

static struct modlstrmod modlstrmod = {
	&mod_strmodops,
	(char *)sppptun_module_description,
	&sppptun_fmodsw
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlstrmod,
	(void *)&modldrv,
	NULL
};

int
_init(void)
{
	int retv;

	sppptun_init();
	if ((retv = mod_install(&modlinkage)) == 0)
		sppptun_tcl_init();
	return (retv);
}

int
_fini(void)
{
	int retv;

	if ((retv = sppptun_tcl_fintest()) != 0)
		return (retv);
	retv = mod_remove(&modlinkage);
	if (retv != 0)
		return (retv);
	sppptun_tcl_fini();
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * tun_attach()
 *
 * Description:
 *    Attach a PPP tunnel driver to the system.
 */
static int
tun_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);
	if (ddi_create_minor_node(dip, PPP_TUN_NAME, S_IFCHR, 0, DDI_PSEUDO,
	    CLONE_DEV) == DDI_FAILURE) {
		ddi_remove_minor_node(dip, NULL);
		return (DDI_FAILURE);
	}
	tun_dev_info = dip;
	return (DDI_SUCCESS);
}

/*
 * tun_detach()
 *
 * Description:
 *    Detach an interface to the system.
 */
static int
tun_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);
	tun_dev_info = NULL;
	ddi_remove_minor_node(dip, NULL);
	return (DDI_SUCCESS);
}

/*
 * tun_info()
 *
 * Description:
 *    Translate "dev_t" to a pointer to the associated "dev_info_t".
 */
/* ARGSUSED */
static int
tun_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
	void **result)
{
	int	rc;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (tun_dev_info == NULL) {
			rc = DDI_FAILURE;
		} else {
			*result = (void *)tun_dev_info;
			rc = DDI_SUCCESS;
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = NULL;
		rc = DDI_SUCCESS;
		break;
	default:
		rc = DDI_FAILURE;
		break;
	}
	return (rc);
}
