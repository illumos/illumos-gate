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
 * The driver portion of kmdb, which manages /dev/kmdb and passes requests along
 * to the kmdb misc module (kmdbmod).
 */

#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/open.h>
#include <sys/kobj.h>
#include <sys/kdi.h>
#include <sys/policy.h>
#include <sys/kobj_impl.h>
#include <sys/kmdb.h>
#include <sys/sysmacros.h>
#include <sys/consdev.h>

#define	KDRV_CFG_MAXLEN		2048

static dev_info_t 		*kdrv_dip;

/*ARGSUSED*/
static int
kdrv_open(dev_t *dev, int openflags, int otyp, cred_t *credp)
{
	if (otyp != OTYP_CHR)
		return (EINVAL);

	if (secpolicy_kmdb(credp) != 0)
		return (EPERM);

	return (0);
}

/*ARGSUSED*/
static int
kdrv_close(dev_t dev, int openflags, int otyp, cred_t *credp)
{
	return (0);
}

typedef struct kdrv_flags_map {
	const char *fm_name;
	int fm_defval;
	uint_t fm_flag;
} kdrv_flags_map_t;

static const kdrv_flags_map_t kdrv_flags_map[] = {
	{ "kmdb-auto-entry", 1, KMDB_F_AUTO_ENTRY },
	{ "kmdb-trap-noswitch", 0, KMDB_F_TRAP_NOSWITCH },
	{ "kmdb-driver-debug", 0, KMDB_F_DRV_DEBUG },
	{ NULL }
};

static int
kdrv_activate(intptr_t arg)
{
	uint_t flags;
	size_t memsz;
	char *cfg;
	size_t got;
	int i, rc;

#if defined(__x86)
	if (cons_polledio == NULL) {
		cmn_err(CE_NOTE, "kmdb not supported: no console polled I/O");
		return (ENOTSUP);
	}
#endif

	memsz = ddi_prop_get_int(DDI_DEV_T_ANY, kdrv_dip,
	    DDI_PROP_DONTPASS, "kmdb-memseg-size", 0);

	for (flags = 0, i = 0; kdrv_flags_map[i].fm_name != NULL; i++) {
		const kdrv_flags_map_t *fm = &kdrv_flags_map[i];
		if (ddi_prop_get_int(DDI_DEV_T_ANY, kdrv_dip, DDI_PROP_DONTPASS,
		    (char *)fm->fm_name, fm->fm_defval))
			flags |= fm->fm_flag;
	}

	cfg = kmem_alloc(KDRV_CFG_MAXLEN, KM_SLEEP);

	if ((rc = copyinstr((caddr_t)arg, cfg, KDRV_CFG_MAXLEN, &got)) != 0) {
		kmem_free(cfg, KDRV_CFG_MAXLEN);
		return (rc == ENAMETOOLONG ? E2BIG : EFAULT);
	}

	rc = kctl_modload_activate(memsz, cfg, flags);

	kmem_free(cfg, KDRV_CFG_MAXLEN);

	return (rc);
}

static int
kdrv_deactivate(void)
{
	return (kctl_deactivate());
}

/*ARGSUSED*/
static int
kdrv_ioctl(dev_t dev, int cmd, intptr_t arg, int flags, cred_t *credp,
    int *rvalp)
{
	switch (cmd) {
	case KMDB_IOC_START:
		return (kdrv_activate(arg));

	case KMDB_IOC_STOP:
		return (kdrv_deactivate());

	default:
		return (EINVAL);
	}
}

/*ARGSUSED*/
static int
kdrv_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int error = DDI_SUCCESS;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = kdrv_dip;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)getminor((dev_t)arg);
		break;
	default:
		*result = NULL;
		error = DDI_FAILURE;
	}

	return (error);
}

static int
kdrv_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (ddi_create_minor_node(dip, ddi_get_name(dip), S_IFCHR,
	    ddi_get_instance(dip), DDI_PSEUDO, 0) != DDI_SUCCESS)
		return (DDI_FAILURE);

	kdrv_dip = dip;

	if (kctl_attach(dip) != 0)
		return (DDI_FAILURE);

	return (DDI_SUCCESS);
}

static int
kdrv_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	if (kctl_detach() == EBUSY)
		return (DDI_FAILURE);

	ddi_remove_minor_node(dip, NULL);

	return (DDI_SUCCESS);
}

static struct cb_ops kdrv_cb_ops = {
	kdrv_open,
	kdrv_close,
	nodev,			/* not a block driver	*/
	nodev,			/* no print routine	*/
	nodev,			/* no dump routine	*/
	nodev,			/* no read routine	*/
	nodev,			/* no write routine	*/
	kdrv_ioctl,
	nodev,			/* no devmap routine	*/
	nodev,			/* no mmap routine	*/
	nodev,			/* no segmap routine	*/
	nochpoll,		/* no chpoll routine	*/
	ddi_prop_op,
	0,			/* not a STREAMS driver	*/
	D_NEW | D_MP,		/* safe for multi-thread/multi-processor */
};

static struct dev_ops kdrv_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	kdrv_getinfo,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	kdrv_attach,		/* devo_attach */
	kdrv_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&kdrv_cb_ops,		/* devo_cb_ops */
	(struct bus_ops *)0,	/* devo_bus_ops */
	NULL,			/* devo_power */
	ddi_quiesce_not_needed,		/* devo_quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"kmdb driver",
	&kdrv_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
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
