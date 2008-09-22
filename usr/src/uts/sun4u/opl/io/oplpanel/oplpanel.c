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
 * All Rights Reserved, Copyright (c) FUJITSU LIMITED 2006
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <sys/types.h>
#include <sys/time.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/param.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/file.h>
#include <sys/intr.h>
#include <sys/machsystm.h>

#define	PNLIE_MASK	0x010	/* interrupt enable/disable */
#define	PNLINT_MASK	0x001	/* interrupted flag */

#ifdef DEBUG
int panel_debug = 0;
static void panel_ddi_put8(ddi_acc_handle_t, uint8_t *, uint8_t);
#define	DCMN_ERR(x)	if (panel_debug) cmn_err x

#else

#define	DCMN_ERR(x)
#define	panel_ddi_put8(x, y, z)	ddi_put8(x, y, z)

#endif

static int	panel_getinfo(dev_info_t *, ddi_info_cmd_t, void *,  void **);
static int	panel_attach(dev_info_t *, ddi_attach_cmd_t);
static int	panel_detach(dev_info_t *, ddi_detach_cmd_t);
static uint_t	panel_intr(caddr_t);
static int	panel_open(dev_t *, int, int, cred_t *);
static int	panel_close(dev_t, int, int, cred_t *);

static char	*panel_name = "oplpanel";
int		panel_enable = 1;	/* enable or disable */

extern uint64_t	cpc_level15_inum;	/* in cpc_subr.c */

struct panel_state {
	dev_info_t		*dip;
	ddi_iblock_cookie_t	iblock_cookie;
	ddi_acc_handle_t	panel_regs_handle;
	uint8_t			*panelregs;		/* mapping address */
	uint8_t			panelregs_state;	/* keeping regs. */
};

struct cb_ops panel_cb_ops = {
	nodev,		/* open */
	nodev,		/* close */
	nodev,		/* strategy */
	nodev,		/* print */
	nodev,		/* dump */
	nodev,		/* read */
	nodev,		/* write */
	nodev,		/* ioctl */
	nodev,		/* devmap */
	nodev,		/* mmap */
	nodev,		/* segmap */
	nochpoll,	/* poll */
	nodev,		/* prop_op */
	NULL,		/* streamtab */
	D_NEW | D_MP | D_HOTPLUG,	/* flag */
	CB_REV,		/* cb_rev */
	nodev,		/* async I/O read entry point */
	nodev		/* async I/O write entry point */
};

static struct dev_ops panel_dev_ops = {
	DEVO_REV,		/* driver build version */
	0,			/* device reference count */
	panel_getinfo,		/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	panel_attach,		/* attach */
	panel_detach,		/* detach */
	nulldev,		/* reset */
	&panel_cb_ops,		/* cb_ops */
	NULL,			/* bus_ops */
	nulldev,		/* power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

/* module configuration stuff */
static void		*panelstates;
extern struct mod_ops	mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,
	"OPL panel driver",
	&panel_dev_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	0
};


int
_init(void)
{
	int	status;

	DCMN_ERR((CE_CONT, "%s: _init\n", panel_name));

	status = ddi_soft_state_init(&panelstates,
	    sizeof (struct panel_state), 0);
	if (status != 0) {
		cmn_err(CE_WARN, "%s: ddi_soft_state_init failed.",
		    panel_name);
		return (status);
	}

	status = mod_install(&modlinkage);
	if (status != 0) {
		ddi_soft_state_fini(&panelstates);
	}

	return (status);
}

int
_fini(void)
{
	/*
	 * Can't unload to make sure the panel switch always works.
	 */
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
panel_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{

	int instance;
	struct panel_state *statep = NULL;

	ddi_device_acc_attr_t access_attr = {
		DDI_DEVICE_ATTR_V0,
		DDI_STRUCTURE_BE_ACC,
		DDI_STRICTORDER_ACC
	};

	instance = ddi_get_instance(dip);

	DCMN_ERR((CE_CONT, "%s%d: attach\n", panel_name, instance));

	switch (cmd) {
	case DDI_ATTACH:
		DCMN_ERR((CE_CONT, "%s%d: DDI_ATTACH\n",
		    panel_name, instance));
		break;

	case DDI_RESUME:
		DCMN_ERR((CE_CONT, "%s%d: DDI_RESUME\n",
		    panel_name, instance));

		if ((statep = (struct panel_state *)
		    ddi_get_soft_state(panelstates, instance)) == NULL) {
			cmn_err(CE_WARN, "%s%d: ddi_get_soft_state failed.",
			    panel_name, instance);
			return (DDI_FAILURE);
		}

		/* enable the interrupt just in case */
		panel_ddi_put8(statep->panel_regs_handle, statep->panelregs,
		    statep->panelregs_state);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	/*
	 * Attach routine
	 */

	/* alloc and get soft state */
	if (ddi_soft_state_zalloc(panelstates, instance) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: ddi_soft_state_zalloc failed.",
		    panel_name, instance);
		goto attach_failed2;
	}
	if ((statep = (struct panel_state *)
	    ddi_get_soft_state(panelstates, instance)) == NULL) {
		cmn_err(CE_WARN, "%s%d: ddi_get_soft_state failed.",
		    panel_name, instance);
		goto attach_failed1;
	}

	/* set the dip in the soft state */
	statep->dip = dip;

	/* mapping register */
	if (ddi_regs_map_setup(dip, 0, (caddr_t *)&statep->panelregs,
	    0, 0, /* the entire space is mapped */
	    &access_attr, &statep->panel_regs_handle) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: ddi_regs_map_setup failed.",
		    panel_name, instance);
		goto attach_failed1;
	}

	/* setup the interrupt handler */
	ddi_get_iblock_cookie(dip, 0, &statep->iblock_cookie);
	if (ddi_add_intr(dip, 0, &statep->iblock_cookie, 0, &panel_intr,
	    (caddr_t)statep) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: cannot add interrupt handler.",
		    panel_name, instance);
		goto attach_failed0;
	}

	/* ATTACH SUCCESS */

	/* announce the device */
	ddi_report_dev(dip);

	/* turn on interrupt */
	statep->panelregs_state = 0 | PNLIE_MASK;
	panel_ddi_put8(statep->panel_regs_handle, statep->panelregs,
	    statep->panelregs_state);

	return (DDI_SUCCESS);

attach_failed0:
	ddi_regs_map_free(&statep->panel_regs_handle);
attach_failed1:
	ddi_soft_state_free(panelstates, instance);
attach_failed2:
	DCMN_ERR((CE_NOTE, "%s%d: attach failed", panel_name, instance));
	return (DDI_FAILURE);
}

static int
panel_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance;
	struct panel_state *statep;

	instance = ddi_get_instance(dip);

	DCMN_ERR((CE_CONT, "%s%d: detach\n", panel_name, instance));

	if ((statep = (struct panel_state *)
	    ddi_get_soft_state(panelstates, instance)) == NULL) {
		cmn_err(CE_WARN, "%s%d: ddi_get_soft_state failed.",
		    panel_name, instance);
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_DETACH:
		DCMN_ERR((CE_CONT, "%s%d: DDI_DETACH\n",
		    panel_name, instance));

		/* turn off interrupt */
		statep->panelregs_state &= ~PNLIE_MASK;
		panel_ddi_put8(statep->panel_regs_handle, statep->panelregs,
		    statep->panelregs_state);

		/* free all resources for the dip */
		ddi_remove_intr(dip, 0, statep->iblock_cookie);

		/* need not free iblock_cookie */
		ddi_regs_map_free(&statep->panel_regs_handle);
		ddi_soft_state_free(panelstates, instance);

		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		DCMN_ERR((CE_CONT, "%s%d: DDI_SUSPEND\n",
		    panel_name, instance));
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);

	}
	/* Not reached */
}

/*ARGSUSED*/
static int
panel_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,  void **resultp)
{
	struct panel_state *statep;
	int	instance;
	dev_t	dev = (dev_t)arg;

	instance = getminor(dev);

	DCMN_ERR((CE_CONT, "%s%d: getinfo\n", panel_name, instance));

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if ((statep = (struct panel_state *)
		    ddi_get_soft_state(panelstates, instance)) == NULL) {
			cmn_err(CE_WARN, "%s%d: ddi_get_soft_state failed.",
			    panel_name, instance);
			*resultp = NULL;
			return (DDI_FAILURE);
		}
		*resultp = statep->dip;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*resultp = (void *)(uintptr_t)instance;
		break;
	default:
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static  uint_t
panel_intr(caddr_t arg)
{
	struct panel_state *statep = (struct panel_state *)arg;

	/* to confirm the validity of the interrupt */
	if (!(ddi_get8(statep->panel_regs_handle, statep->panelregs) &
	    PNLINT_MASK)) {
		return (DDI_INTR_UNCLAIMED);
	}

	/*
	 * Clear the PNLINT bit
	 * HW reported that there might be a delay in the PNLINT bit
	 * clearing. We force synchronization by attempting to read
	 * back the reg after clearing the bit.
	 */
	panel_ddi_put8(statep->panel_regs_handle, statep->panelregs,
	    statep->panelregs_state | PNLINT_MASK);
	ddi_get8(statep->panel_regs_handle, statep->panelregs);

	if (panel_enable) {
		uint_t pstate_save;

		/* avoid double panic */
		panel_enable 	= 0;

		/*
		 * Re-enqueue the cpc interrupt handler for PIL15 here since we
		 * are not unwinding back to the interrupt handler subsystem.
		 * This is to allow potential cpc overflow interrupts to
		 * function while we go thru the panic flow. Note that this
		 * logic could be implemented in panic_enter_hw(), we do
		 * it here for now as it is less risky. This particular
		 * condition is only specific to OPL hardware and we want
		 * to minimize exposure of this new logic to other existing
		 * platforms.
		 */
		pstate_save = disable_vec_intr();
		intr_enqueue_req(PIL_15, cpc_level15_inum);
		enable_vec_intr(pstate_save);

		cmn_err(CE_PANIC,
		    "System Panel Driver: Emergency panic request "
		    "detected!");
		/* Not reached */
	}

	return (DDI_INTR_CLAIMED);
}

#ifdef DEBUG
static void
panel_ddi_put8(ddi_acc_handle_t handle, uint8_t *dev_addr, uint8_t value)
{
	if (panel_debug) {
		cmn_err(CE_CONT, "%s: old value = 0x%x\n",
		    panel_name, ddi_get8(handle, dev_addr));
		cmn_err(CE_CONT, "%s: writing value = 0x%x\n",
		    panel_name, value);
		ddi_put8(handle, dev_addr, value);
		cmn_err(CE_CONT, "%s: new value = 0x%x\n",
		    panel_name, ddi_get8(handle, dev_addr));
	} else {
		ddi_put8(handle, dev_addr, value);
	}
}
#endif
