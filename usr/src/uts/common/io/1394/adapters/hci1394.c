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
 * hci1394.c
 *    1394 (firewire) OpenHCI 1.0 HBA driver. This file contains the driver's
 *    _init(), _info(), and _fini().
 */

#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/1394/ieee1394.h>
#include <sys/1394/h1394.h>

#include <sys/1394/adapters/hci1394.h>


/* HAL State Pointer */
void *hci1394_statep;

/* Character/Block Operations */
static struct cb_ops hci1394_cb_ops = {
	hci1394_open,		/* open */
	hci1394_close,		/* close */
	nodev,			/* strategy (block) */
	nodev,			/* print (block) */
	nodev,			/* dump (block) */
	nodev,			/* read */
	nodev,			/* write */
	hci1394_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* chpoll */
	ddi_prop_op,		/* prop_op */
	NULL,			/* streams */
	D_NEW | D_MP |
	D_64BIT | D_HOTPLUG,	/* flags */
	CB_REV			/* rev */
};

/* Driver Operations */
static struct dev_ops hci1394_ops = {
	DEVO_REV,		/* struct rev */
	0,			/* refcnt */
	hci1394_getinfo,	/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	hci1394_attach,		/* attach */
	hci1394_detach,		/* detach */
	nodev,			/* reset */
	&hci1394_cb_ops,	/* cb_ops */
	NULL,			/* bus_ops */
	NULL,			/* power */
	hci1394_quiesce,	/* devo_quiesce */
};

/* Module Driver Info */
static struct modldrv hci1394_modldrv = {
	&mod_driverops,
	"1394 OpenHCI HBA driver",
	&hci1394_ops
};

/* Module Linkage */
static struct modlinkage hci1394_modlinkage = {
	MODREV_1,
	&hci1394_modldrv,
	NULL
};

#ifndef NPROBE
extern int tnf_mod_load(void);
extern int tnf_mod_unload(struct modlinkage *mlp);
#endif

int
_init()
{
	int status;


#ifndef NPROBE
	(void) tnf_mod_load();
#endif
	TNF_PROBE_0_DEBUG(hci1394_init_enter, HCI1394_TNF_HAL_STACK, "");

	status = ddi_soft_state_init(&hci1394_statep, sizeof (hci1394_state_t),
	    (size_t)HCI1394_INITIAL_STATES);
	if (status != 0) {
		TNF_PROBE_2(hci1394_init_ssi_fail, HCI1394_TNF_HAL_ERROR, "",
		    tnf_string, errmsg, "failed in ddi_soft_state_init",
		    tnf_int, error, status);
		TNF_PROBE_0_DEBUG(hci1394_init_exit, HCI1394_TNF_HAL_STACK, "");
#ifndef NPROBE
		(void) tnf_mod_unload(&hci1394_modlinkage);
#endif
		return (status);
	}

	/* Call into services layer to init bus-ops */
	status = h1394_init(&hci1394_modlinkage);
	if (status != 0) {
		TNF_PROBE_2(hci1394_init_h1394_fail, HCI1394_TNF_HAL_ERROR, "",
		    tnf_string, errmsg, "failed in h1394_init",
		    tnf_int, error, status);
		TNF_PROBE_0_DEBUG(hci1394_init_exit, HCI1394_TNF_HAL_STACK, "");
#ifndef NPROBE
		(void) tnf_mod_unload(&hci1394_modlinkage);
#endif
		return (status);
	}

	status = mod_install(&hci1394_modlinkage);
	if (status != 0) {
		TNF_PROBE_2(hci1394_init_modi_fail, HCI1394_TNF_HAL_ERROR, "",
		    tnf_string, errmsg, "failed in mod_install",
		    tnf_int, error, status);
		ddi_soft_state_fini(&hci1394_statep);
#ifndef NPROBE
		(void) tnf_mod_unload(&hci1394_modlinkage);
#endif
		return (status);
	}

	TNF_PROBE_0_DEBUG(hci1394_init_exit, HCI1394_TNF_HAL_STACK, "");

	return (status);
}


int
_info(struct modinfo *modinfop)
{
	int status;

	TNF_PROBE_0_DEBUG(hci1394_info_enter, HCI1394_TNF_HAL_STACK, "");
	status = mod_info(&hci1394_modlinkage, modinfop);
	TNF_PROBE_0_DEBUG(hci1394_info_exit, HCI1394_TNF_HAL_STACK, "");

	return (status);
}


int
_fini()
{
	int status;

	TNF_PROBE_0_DEBUG(hci1394_fini_enter, HCI1394_TNF_HAL_STACK, "");

	status = mod_remove(&hci1394_modlinkage);
	if (status != 0) {
		TNF_PROBE_2(hci1394_fini_modr_fail, HCI1394_TNF_HAL_ERROR, "",
		    tnf_string, errmsg, "failed in mod_remove",
		    tnf_int, error, status);
		TNF_PROBE_0_DEBUG(hci1394_fini_exit, HCI1394_TNF_HAL_STACK, "");
		return (status);
	}

	/* Call into services layer notify about _fini */
	h1394_fini(&hci1394_modlinkage);
	ddi_soft_state_fini(&hci1394_statep);

	TNF_PROBE_0_DEBUG(hci1394_fini_exit, HCI1394_TNF_HAL_STACK, "");

#ifndef NPROBE
	(void) tnf_mod_unload(&hci1394_modlinkage);
#endif

	return (status);
}
