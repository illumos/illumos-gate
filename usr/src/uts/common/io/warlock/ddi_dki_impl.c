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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * ddi_dki_impl.c - A pseudo-kernel to use when analyzing drivers with warlock.
 *
 * The main idea here is to represent all of the ways that the kernel can
 * call into the driver, so that warlock has the correct view of the call
 * graph.
 *
 * This version differs from ddi_dki_spec.c in that it represents the
 * current implementation of the DDI/DKI rather than the specification.
 */
#include "ddi_dki_comm.inc"
#include <sys/esunddi.h>
#include <sys/sunndi.h>
#include <sys/ddi.h>
#include <sys/epm.h>
#include <sys/proc.h>

int warlock_dummy(void);
int _init(void);
int _fini(void);
int _info(struct modinfo *a);
int scsi_init(void);

int main(void) {

	/*
	 * The following call will cause warlock to know about
	 * warlock_dummy as a func that can be used to satisfy
	 * unbound function pointers.  It shouldn't be needed
	 * with the new warlock on suntools.
	 */
	warlock_dummy();

	/*
	 * When the following functions are called, there is never
	 * more than one thread running in the driver.
	 */
	_init();
	_fini();
	_info(0);
	(*devops_p->devo_identify)(0);
	(*devops_p->devo_probe)(0);
	(*devops_p->devo_attach)(0, 0);

	/*
	 * When the following functions are called, there may be
	 * more than one thread running in the driver.
	 */
	_NOTE(COMPETING_THREADS_NOW)


	scsi_init();

	(*devops_p->devo_getinfo)(0, 0, 0, 0);
	(*devops_p->devo_reset)(0, 0);
	(*devops_p->devo_power)(0, 0, 0);

	(*cbops_p->cb_open)(0, 0, 0, 0);
	(*cbops_p->cb_close)(0, 0, 0, 0);
	(*cbops_p->cb_strategy)(0);
	(*cbops_p->cb_print)(0, 0);
	(*cbops_p->cb_dump)(0, 0, 0, 0);
	(*cbops_p->cb_read)(0, 0, 0);
	(*cbops_p->cb_write)(0, 0, 0);
	(*cbops_p->cb_ioctl)(0, 0, 0, 0, 0, 0);
	(*cbops_p->cb_devmap)(0, 0, 0, 0, 0, 0);
	(*cbops_p->cb_mmap)(0, 0, 0);
	(*cbops_p->cb_segmap)(0, 0, 0, 0, 0, 0, 0, 0, 0);
	(*cbops_p->cb_chpoll)(0, 0, 0, 0, 0);
	(*cbops_p->cb_prop_op)(0, 0, 0, 0, 0, 0, 0);
	(*cbops_p->cb_aread)(0, 0, 0);
	(*cbops_p->cb_awrite)(0, 0, 0);

	(*busops_p->bus_map)(0, 0, 0, 0, 0, 0);
	(*busops_p->bus_get_intrspec)(0, 0, 0);
	(*busops_p->bus_add_intrspec)(0, 0, 0, 0, 0, 0, 0, 0);
	(*busops_p->bus_remove_intrspec)(0, 0, 0, 0);
	(*busops_p->bus_map_fault)(0, 0, 0, 0, 0, 0, 0, 0, 0);
	(*busops_p->bus_dma_map)(0, 0, 0, 0);
	(*busops_p->bus_dma_allochdl)(0, 0, 0, 0, 0, 0);
	(*busops_p->bus_dma_freehdl)(0, 0, 0);
	(*busops_p->bus_dma_bindhdl)(0, 0, 0, 0, 0, 0);
	(*busops_p->bus_dma_unbindhdl)(0, 0, 0);
	(*busops_p->bus_dma_flush)(0, 0, 0, 0, 0, 0);
	(*busops_p->bus_dma_win)(0, 0, 0, 0, 0, 0, 0, 0);
	(*busops_p->bus_dma_ctl)(0, 0, 0, 0, 0, 0, 0, 0);
	(*busops_p->bus_ctl)(0, 0, 0, 0, 0);
	(*busops_p->bus_prop_op)(0, 0, 0, 0, 0, 0, 0, 0);

	(*busops_p->bus_get_eventcookie)(0, 0, 0, 0);
	(*busops_p->bus_add_eventcall)(0, 0, 0, 0, 0, 0);
	(*busops_p->bus_remove_eventcall)(0, 0);
	(*busops_p->bus_post_event)(0, 0, 0, 0);
	(*busops_p->bus_intr_ctl)(0, 0, 0, 0, 0);

	(*busops_p->bus_config)(0, 0, 0, 0, 0);
	(*busops_p->bus_unconfig)(0, 0, 0, 0);

#ifndef __lock_lint
/* this causes warnings and it is unclear how to handle this */
	(*busops_p->bus_fm_init)(0, 0, 0, 0);
	(*busops_p->bus_fm_fini)(0, 0);
	(*busops_p->bus_fm_access_enter)(0, 0);
	(*busops_p->bus_fm_access_exit)(0, 0);
	(*busops_p->bus_power)(0, 0, 0, 0, 0);
	(*busops_p->bus_intr_op)(0, 0, 0, 0, 0);
#endif

	ndi_devi_offline(0, 0);
	_NOTE(NO_COMPETING_THREADS_NOW)
}

	/* Power managment framework calls */
int
pm_set_power(dev_info_t *dip, int comp, int level, int direction,
    pm_canblock_t canblock, int scan, int *retp)
{
	(*devops_p->devo_power)(0, 0, 0);
}

int
pm_raise_power(dev_info_t *dip, int comp, int level) {
	(*devops_p->devo_power)(0, 0, 0);
}

int
pm_lower_power(dev_info_t *dip, int comp, int level) {
	(*devops_p->devo_power)(0, 0, 0);
}

static kmutex_t mutex;
static kcondvar_t cv;

void
delay(clock_t ticks)
{
	mutex_enter(&mutex);
	cv_wait(&cv, &mutex);
	mutex_exit(&mutex);
}

void
putnext(queue_t *q, mblk_t *mp)
{
	mutex_enter(&mutex);
	cv_wait(&cv, &mutex);
	mutex_exit(&mutex);
}

int
ndi_devi_offline(dev_info_t *dip, uint_t flags) {
	(*busops_p->bus_dma_ctl)(0, 0, 0, 0, 0, 0, 0, 0);
	(*busops_p->bus_ctl)(0, 0, 0, 0, 0);
	(*busops_p->bus_get_eventcookie)(0, 0, 0, 0);
	(*busops_p->bus_add_eventcall)(0, 0, 0, 0, 0, 0);
	(*busops_p->bus_remove_eventcall)(0, 0);
	(*busops_p->bus_post_event)(0, 0, 0, 0);
	(*busops_p->bus_unconfig)(0, 0, 0, 0);
}

int
ndi_devi_online(dev_info_t *dip, uint_t flags) {
	(*busops_p->bus_config)(0, 0, 0, 0, 0);
}
