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
 * Copyright 2007 Sun Microsystems, Inc.
 * All rights reserved.  Use is subject to license terms.
 */

/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 */

/*
 * ddi_dki_comm.inc - Part of a pseudo-kernel to use when analyzing drivers
 * with warlock.
 *
 * The main idea here is to represent all of the ways that the kernel can
 * call into the driver, so that warlock has the correct view of the call
 * graph.
 *
 * This file represents the stuff in common between the DDI/DKI spec and
 * the current implementation.	It is included by both ddi_dki_{spec,impl}.c
 *
 * This is a SPARC version; some functions (e.g. ddi_dma_nextwin) should
 * be changed for an x86 version.
 */

#include <sys/note.h>
#include <sys/devops.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/proc.h>

_NOTE(DATA_READABLE_WITHOUT_LOCK( dev_ops cb_ops bus_ops ))

/*
 * Now define a dev_ops, a cb_ops, and a bus_ops with 0 for each
 * entry point, so that warlock doesn't complain that these
 * function pointers have no bindings.
 *	1  2  3  4  5  6  7  8	9 10 11 12 13 14 15 16 17 18 19 20 21 22
 */
struct dev_ops *devops_p, warlock_dev_ops = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

struct cb_ops *cbops_p, warlock_cb_ops = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

struct bus_ops *busops_p, warlock_bus_ops = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};


/* This rendition of mod_remove() tells warlock that it calls detach. */
int
mod_remove(struct modlinkage *a) {
	(*devops_p->devo_detach)(NULL, 0);
}

/* This rendition of physio() shows that it calls its func ptr args. */
int
physio(
	int (*strategy)(struct buf *),
	struct buf *a,
	dev_t b,
	int c,
	void (*mincnt)(struct buf *),
	struct uio *d)
{
	(*strategy)(0);
	(*mincnt)(0);
}

/*
 * Tell warlock that args to some funcs get called back as separate threads.
 */
timeout_id_t
timeout(void (*fp)(void *), void *a, clock_t b)
{
	thread_create(0, 0, (void (*)())fp, 0, 0, 0, 0, 0);
}

int
ddi_add_intr(dev_info_t *a, uint_t b, ddi_iblock_cookie_t *c,
	ddi_idevice_cookie_t *d, uint_t (*fp)(caddr_t), caddr_t e)
{
	thread_create(0, 0, (void (*)())fp, 0, 0, 0, 0, 0);
}

int
ddi_add_softintr(dev_info_t *a, int b, ddi_softintr_t *c,
    ddi_iblock_cookie_t *d, ddi_idevice_cookie_t *e, uint_t (*fp)(caddr_t),
    caddr_t f)
{
	thread_create(0, 0, (void (*)())fp, 0, 0, 0, 0, 0);
}

int
ddi_intr_add_handler(ddi_intr_handle_t h, ddi_intr_handler_t inthandler,
    void *arg1, void *arg2)
{
	thread_create(0, 0, (void (*)())inthandler, 0, 0, 0, 0, 0);
}

int
ddi_intr_add_softint(dev_info_t *dip, ddi_softint_handle_t *h_p, int soft_pri,
    ddi_intr_handler_t handler, void *arg1)
{
	thread_create(0, 0, (void (*)())handler, 0, 0, 0, 0, 0);
}

int
ddi_dma_addr_setup(
	dev_info_t *a,
	struct as *b,
	caddr_t c,
	size_t d,
	uint_t e,
	int (*fp)(void),
	caddr_t f,
	ddi_dma_lim_t *g,
	ddi_dma_handle_t *h)
{
	struct bus_ops *ops;
	(*ops->bus_dma_map)(0, 0, 0, 0);
	thread_create(0, 0, (void (*)())fp, 0, 0, 0, 0, 0);
}

int
ddi_dma_buf_setup(
	dev_info_t *a,
	struct buf *b,
	uint_t c,
	int (*fp)(void),
	caddr_t d,
	ddi_dma_lim_t *e,
	ddi_dma_handle_t *f)
{
	struct bus_ops *ops;
	(*ops->bus_dma_map)(0, 0, 0, 0);
	thread_create(0, 0, (void (*)())fp, 0, 0, 0, 0, 0);
}

void
ddi_set_callback(
	int (*fp)(caddr_t),
	caddr_t a,
	uintptr_t *b)
{
	thread_create(0, 0, (void (*)())fp, 0, 0, 0, 0, 0);
}

int
ddi_dma_mctl(dev_info_t *a, dev_info_t *b, ddi_dma_handle_t c,
	enum ddi_dma_ctlops d, off_t *e, size_t *f, caddr_t *g,
	uint_t h)
{
	struct bus_ops *ops;
	(*ops->bus_dma_ctl)(0, 0, 0, 0, 0, 0, 0, 0);
}

int
ddi_dma_get_error(ddi_dma_handle_t h, uint_t len, caddr_t errblk)
{
	struct bus_ops *ops;
	(*ops->bus_dma_ctl)(0, 0, 0, 0, 0, 0, 0, 0);
}

int
ddi_dma_sync(ddi_dma_handle_t h, off_t o, size_t l, uint_t whom)
{
	struct bus_ops *ops;
	(*ops->bus_dma_ctl)(0, 0, 0, 0, 0, 0, 0, 0);
}

int
ddi_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op, int mod_flags,
    char *name, caddr_t valuep, int *lengthp)
{
	struct bus_ops *ops;
	(*ops->bus_prop_op)(0, 0, 0, 0, 0, 0, 0, 0);
}

int
ddi_add_event_handler(dev_info_t *dip, ddi_eventcookie_t event,
    void (*handler)(dev_info_t *, ddi_eventcookie_t, void *, void *),
    void *arg, ddi_callback_id_t *id)
{
	struct bus_ops *ops;
	return ((*ops->bus_add_eventcall)(dip, dip, event, handler, arg, id));
}

int
ddi_remove_event_handler(ddi_callback_id_t id)
{
	dev_info_t *dip;
	struct bus_ops *ops;
	return ((*ops->bus_remove_eventcall)(dip, id));
}


int
ddi_get_eventcookie(dev_info_t *dip, char *name,
    ddi_eventcookie_t *event_cookiep)
{
	struct bus_ops *ops;
	return ((*ops->bus_get_eventcookie)(dip, dip,
	    name, event_cookiep));
}
