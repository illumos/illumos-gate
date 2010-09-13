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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
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
 * Implementation.
 */

void
sda_host_init_ops(struct dev_ops *devops)
{
	bd_mod_init(devops);
}

void
sda_host_fini_ops(struct dev_ops *devops)
{
	bd_mod_fini(devops);
}

sda_host_t *
sda_host_alloc(dev_info_t *dip, int nslot, sda_ops_t *ops, ddi_dma_attr_t *dma)
{
	sda_host_t	*h;

	if (ops->so_version != SDA_OPS_VERSION) {
		return (NULL);
	}

	h = kmem_zalloc(sizeof (*h), KM_SLEEP);
	h->h_nslot = nslot;
	h->h_slots = kmem_zalloc(sizeof (sda_slot_t) * nslot, KM_SLEEP);
	h->h_dma = dma;
	h->h_dip = dip;

	/* initialize each slot */
	for (int i = 0; i < nslot; i++) {
		sda_slot_t *slot = &h->h_slots[i];

		slot->s_hostp = h;
		slot->s_slot_num = i;
		slot->s_ops = *ops;

		sda_slot_init(slot);
	}

	return (h);
}

void
sda_host_free(sda_host_t *h)
{
	for (int i = 0; i < h->h_nslot; i++) {
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
	/*
	 * Attach slots.
	 */
	for (int i = 0; i < h->h_nslot; i++) {

		sda_slot_attach(&h->h_slots[i]);

		/*
		 * Initiate card detection.
		 */
		sda_host_detect(h, i);
	}

	return (DDI_SUCCESS);
}

void
sda_host_detach(sda_host_t *h)
{
	/*
	 * Detach slots.
	 */
	for (int i = 0; i < h->h_nslot; i++) {
		sda_slot_detach(&h->h_slots[i]);
	}
}

void
sda_host_suspend(sda_host_t *h)
{
	for (int i = 0; i < h->h_nslot; i++) {
		sda_slot_suspend(&h->h_slots[i]);
	}
}

void
sda_host_resume(sda_host_t *h)
{
	for (int i = 0; i < h->h_nslot; i++) {
		sda_slot_resume(&h->h_slots[i]);
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
