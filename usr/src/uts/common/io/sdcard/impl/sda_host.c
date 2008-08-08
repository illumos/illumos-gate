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
 * SD card host support.  This is the API that host drivers access.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/varargs.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sdcard/sda.h>
#include <sys/sdcard/sda_impl.h>

/*
 * Static Variables.
 */

static struct bus_ops sda_host_bus_ops = {
	BUSO_REV,			/* busops_rev */
	nullbusmap,			/* bus_map */
	NULL,				/* bus_get_intrspec (OBSOLETE) */
	NULL,				/* bus_add_intrspec (OBSOLETE) */
	NULL,				/* bus_remove_intrspec (OBSOLETE) */
	i_ddi_map_fault,		/* bus_map_fault */
	ddi_dma_map,			/* bus_dma_map */
	ddi_dma_allochdl,		/* bus_dma_allochdl */
	ddi_dma_freehdl,		/* bus_dma_freehdl */
	ddi_dma_bindhdl,		/* bus_dma_bindhdl */
	ddi_dma_unbindhdl,		/* bus_dma_unbindhdl */
	ddi_dma_flush,			/* bus_dma_flush */
	ddi_dma_win,			/* bus_dma_win */
	ddi_dma_mctl,			/* bus_dma_ctl */
	sda_nexus_bus_ctl,		/* bus_ctl */
	ddi_bus_prop_op,		/* bus_prop_op */
	NULL,				/* bus_get_eventcookie */
	NULL,				/* bus_add_eventcall */
	NULL,				/* bus_remove_eventcall */
	NULL,				/* bus_post_event */
	NULL,				/* bus_intr_ctl (OBSOLETE) */
	NULL, /* sda_nexus_bus_config, */		/* bus_config */
	NULL, /* sda_nexus_bus_unconfig, */		/* bus_unconfig */
	NULL,				/* bus_fm_init */
	NULL,				/* bus_fm_fini */
	NULL,				/* bus_fm_access_enter */
	NULL,				/* bus_fm_access_exit */
	NULL,				/* bus_power */
	NULL,				/* bus_intr_op */
};

static struct cb_ops sda_host_cb_ops = {
	sda_nexus_open,			/* cb_open */
	sda_nexus_close,		/* cb_close */
	nodev,				/* cb_strategy */
	nodev,				/* cb_print */
	nodev,				/* cb_dump */
	nodev,				/* cb_read */
	nodev,				/* cb_write */
	sda_nexus_ioctl,		/* cb_ioctl */
	nodev,				/* cb_devmap */
	nodev,				/* cb_mmap */
	nodev,				/* cb_segmap */
	nochpoll,			/* cb_poll */
	ddi_prop_op,			/* cb_prop_op */
	NULL,				/* cb_str */
	D_MP,				/* cb_flag */
	CB_REV,				/* cb_rev */
	nodev,				/* cb_aread */
	nodev,				/* cb_awrite */
};

/*
 * Implementation.
 */

void
sda_host_init_ops(struct dev_ops *devops)
{
	devops->devo_getinfo = sda_nexus_getinfo;
	devops->devo_cb_ops = &sda_host_cb_ops;
	devops->devo_bus_ops = &sda_host_bus_ops;
}

void
sda_host_fini_ops(struct dev_ops *devops)
{
	devops->devo_bus_ops = NULL;
}

sda_host_t *
sda_host_alloc(dev_info_t *dip, int nslot, sda_ops_t *ops, ddi_dma_attr_t *dma)
{
	sda_host_t	*h;
	int		i;

	if (ops->so_version != SDA_OPS_VERSION) {
		return (NULL);
	}

	h = kmem_zalloc(sizeof (*h), KM_SLEEP);
	h->h_nslot = nslot;
	h->h_slots = kmem_zalloc(sizeof (sda_slot_t) * nslot, KM_SLEEP);
	h->h_dma = dma;
	h->h_dip = dip;

	/* initialize each slot */
	for (i = 0; i < nslot; i++) {
		sda_slot_t *slot = &h->h_slots[i];

		slot->s_host = h;
		slot->s_slot_num = i;
		slot->s_ops = *ops;

		sda_slot_init(slot);
	}

	return (h);
}

void
sda_host_free(sda_host_t *h)
{
	int	i;

	for (i = 0; i < h->h_nslot; i++) {
		sda_slot_fini(&h->h_slots[i]);
	}

	kmem_free(h->h_slots, sizeof (sda_slot_t) * h->h_nslot);
	kmem_free(h, sizeof (*h));
}

void
sda_host_set_private(sda_host_t *h, int num, void *private)
{
	h->h_slots[num].s_prv = private;
}

int
sda_host_attach(sda_host_t *h)
{
	int	i;

	/*
	 * Attach slots.
	 */
	for (i = 0; i < h->h_nslot; i++) {

		sda_slot_attach(&h->h_slots[i]);

		/*
		 * Initiate card detection.
		 */
		sda_host_detect(h, i);
	}

	/*
	 * Register (create) nexus minor nodes.
	 */
	sda_nexus_register(h);

	return (DDI_SUCCESS);
}

void
sda_host_detach(sda_host_t *h)
{
	int	i;

	/*
	 * Unregister nexus minor nodes.
	 */
	sda_nexus_unregister(h);

	/*
	 * Detach slots.
	 */
	for (i = 0; i < h->h_nslot; i++) {
		sda_slot_detach(&h->h_slots[i]);
	}
}

void
sda_host_transfer(sda_host_t *h, int num, sda_err_t errno)
{
	sda_slot_transfer(&h->h_slots[num], errno);
}

void
sda_host_detect(sda_host_t *h, int num)
{
	sda_slot_detect(&h->h_slots[num]);
}

void
sda_host_fault(sda_host_t *h, int num, sda_fault_t fail)
{
	sda_slot_fault(&h->h_slots[num], fail);
}

void
sda_host_log(sda_host_t *h, int snum, const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	if (h != NULL) {
		sda_slot_log(&h->h_slots[snum], fmt, ap);
	} else {
		sda_slot_log(NULL, fmt, ap);
	}
	va_end(ap);
}
