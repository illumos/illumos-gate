/*
 * sppp_mod.c - modload support for PPP pseudo-device driver.
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation is hereby granted, provided that the above copyright
 * notice appears in all copies.
 *
 * SUN MAKES NO REPRESENTATION OR WARRANTIES ABOUT THE SUITABILITY OF
 * THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, OR NON-INFRINGEMENT.  SUN SHALL NOT BE LIABLE FOR
 * ANY DAMAGES SUFFERED BY LICENSEE AS A RESULT OF USING, MODIFYING OR
 * DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES
 *
 * Copyright (c) 1994 The Australian National University.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation is hereby granted, provided that the above copyright
 * notice appears in all copies.  This software is provided without any
 * warranty, express or implied. The Australian National University
 * makes no representations about the suitability of this software for
 * any purpose.
 *
 * IN NO EVENT SHALL THE AUSTRALIAN NATIONAL UNIVERSITY BE LIABLE TO ANY
 * PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF
 * THE AUSTRALIAN NATIONAL UNIVERSITY HAVE BEEN ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * THE AUSTRALIAN NATIONAL UNIVERSITY SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND THE AUSTRALIAN NATIONAL UNIVERSITY HAS NO
 * OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS,
 * OR MODIFICATIONS.
 *
 * This driver is derived from the original SVR4 STREAMS PPP driver
 * originally written by Paul Mackerras <paul.mackerras@cs.anu.edu.au>.
 *
 * Adi Masputra <adi.masputra@sun.com> rewrote and restructured the code
 * for improved performance and scalability.
 */

#define	RCSID	" $Id: sppp_mod.c,v 1.0 2000/05/08 10:53:28 masputra Exp $"

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/ddi.h>
#include <sys/conf.h>
#include <sys/sunddi.h>
#include <sys/stat.h>
#include <sys/kstat.h>
#include <net/pppio.h>
#include <sys/modctl.h>

#include "s_common.h"
#include "sppp.h"

static int	_mi_driver_attach(dev_info_t *, ddi_attach_cmd_t);
static int	_mi_driver_detach(dev_info_t *, ddi_detach_cmd_t);
static int	_mi_driver_info(dev_info_t *, ddi_info_cmd_t, void *, void **);

/*
 * Globals for PPP multiplexer module wrapper
 */
extern const char sppp_module_description[];
static dev_info_t *_mi_dip;

#define	PPP_MI_HIWAT	(PPP_MTU * 16)	/* XXX find more meaningful value */
#define	PPP_MI_LOWAT	(PPP_MTU * 14)	/* XXX find more meaningful value */

static struct module_info sppp_modinfo = {
	PPP_MOD_ID,		/* mi_idnum */
	PPP_DRV_NAME,		/* mi_idname */
	0,			/* mi_minpsz */
	PPP_MAXMTU,		/* mi_maxpsz */
	PPP_MI_HIWAT,		/* mi_hiwat */
	PPP_MI_LOWAT		/* mi_lowat */
};

static struct qinit sppp_urinit = {
	NULL,			/* qi_putp */
	NULL,			/* qi_srvp */
	sppp_open,		/* qi_qopen */
	sppp_close,		/* qi_qclose */
	NULL,			/* qi_qadmin */
	&sppp_modinfo,		/* qi_minfo */
	NULL			/* qi_mstat */
};

static struct qinit sppp_uwinit = {
	sppp_uwput,		/* qi_putp */
	sppp_uwsrv,		/* qi_srvp */
	NULL,			/* qi_qopen */
	NULL,			/* qi_qclose */
	NULL,			/* qi_qadmin */
	&sppp_modinfo,		/* qi_minfo */
	NULL			/* qi_mstat */
};

static struct qinit sppp_lrinit = {
	sppp_lrput,		/* qi_putp */
	sppp_lrsrv,		/* qi_srvp */
	NULL,			/* qi_qopen */
	NULL,			/* qi_qclose */
	NULL,			/* qi_qadmin */
	&sppp_modinfo,		/* qi_minfo */
	NULL			/* qi_mstat */
};

static struct qinit sppp_lwinit = {
	NULL,			/* qi_putp */
	sppp_lwsrv,		/* qi_srvp */
	NULL,			/* qi_qopen */
	NULL,			/* qi_qclose */
	NULL,			/* qi_qadmin */
	&sppp_modinfo,		/* qi_minfo */
	NULL			/* qi_mstat */
};

static struct streamtab sppp_tab = {
	&sppp_urinit,		/* st_rdinit */
	&sppp_uwinit,		/* st_wrinit */
	&sppp_lrinit,		/* st_muxrinit */
	&sppp_lwinit		/* st_muxwrinit */
};

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
DDI_DEFINE_STREAM_OPS(sppp_ops,						\
    nulldev, nulldev,							\
    _mi_driver_attach, _mi_driver_detach, nodev, _mi_driver_info,	\
    D_NEW | D_MP | D_MTQPAIR | D_MTOUTPERIM | D_MTOCEXCL | D_MTPUTSHARED, \
    &sppp_tab, ddi_quiesce_not_supported);

static struct modldrv modldrv = {
	&mod_driverops,				/* drv_modops */
	(char *)sppp_module_description,	/* drv_linkinfo */
	&sppp_ops				/* drv_dev_ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,			/* ml_rev, has to be MODREV_1 */
	&modldrv,			/* ml_linkage, NULL-terminated list */
	NULL				/*  of linkage structures */
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
 * _mi_driver_attach()
 *
 * Description:
 *    Attach a point-to-point interface to the system.
 */
static int
_mi_driver_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}
	_mi_dip = dip;
	if (ddi_create_minor_node(dip, PPP_DRV_NAME, S_IFCHR,
	    0, DDI_PSEUDO, CLONE_DEV) == DDI_FAILURE) {
		ddi_remove_minor_node(dip, NULL);
		return (DDI_FAILURE);
	}
	sppp_dlpi_pinfoinit();
	return (DDI_SUCCESS);
}

/*
 * _mi_driver_detach()
 *
 * Description:
 *    Detach an interface to the system.
 */
static int
_mi_driver_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}
	ddi_remove_minor_node(dip, NULL);
	_mi_dip = NULL;
	return (DDI_SUCCESS);
}

/*
 * _mi_driver_info()
 *
 * Description:
 *    Translate "dev_t" to a pointer to the associated "dev_info_t".
 */
/* ARGSUSED */
static int
_mi_driver_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result)
{
	int	rc;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (_mi_dip == NULL) {
			rc = DDI_FAILURE;
		} else {
			*result = (void *)_mi_dip;
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
