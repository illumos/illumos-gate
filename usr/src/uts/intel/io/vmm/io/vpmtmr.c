/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2014, Neel Natu (neel@freebsd.org)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */
/* This file is dual-licensed; see usr/src/contrib/bhyve/LICENSE */

/*
 * Copyright 2020 Oxide Computer Company
 */

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/kernel.h>
#include <sys/kmem.h>
#include <sys/systm.h>

#include <machine/vmm.h>

#include "vpmtmr.h"

/*
 * The ACPI Power Management timer is a free-running 24- or 32-bit
 * timer with a frequency of 3.579545MHz
 *
 * This implementation will be 32-bits
 */

#define	PMTMR_FREQ	3579545  /* 3.579545MHz */

struct vpmtmr {
	struct vm	*vm;
	void		*io_cookie;
	uint16_t	io_port;
	hrtime_t	base_time;
};

struct vpmtmr *
vpmtmr_init(struct vm *vm)
{
	struct vpmtmr *vpmtmr;

	vpmtmr = kmem_zalloc(sizeof (struct vpmtmr), KM_SLEEP);
	vpmtmr->vm = vm;
	vpmtmr->base_time = gethrtime();

	return (vpmtmr);
}

static int
vpmtmr_detach_ioport(struct vpmtmr *vpmtmr)
{
	if (vpmtmr->io_cookie != NULL) {
		ioport_handler_t old_func;
		void *old_arg;
		int err;

		err = vm_ioport_detach(vpmtmr->vm, &vpmtmr->io_cookie,
		    &old_func, &old_arg);
		if (err != 0) {
			return (err);
		}

		ASSERT3P(old_func, ==, vpmtmr_handler);
		ASSERT3P(old_arg, ==, vpmtmr);
		ASSERT3P(vpmtmr->io_cookie, ==, NULL);
		vpmtmr->io_port = 0;
	}
	return (0);
}

void
vpmtmr_cleanup(struct vpmtmr *vpmtmr)
{
	int err;

	err = vpmtmr_detach_ioport(vpmtmr);
	VERIFY3P(err, ==, 0);

	kmem_free(vpmtmr, sizeof (*vpmtmr));
}

int
vpmtmr_set_location(struct vm *vm, uint16_t ioport)
{
	struct vpmtmr *vpmtmr = vm_pmtmr(vm);
	int err;

	if (vpmtmr->io_cookie != NULL) {
		if (vpmtmr->io_port == ioport) {
			/* already attached in the right place */
			return (0);
		}

		err = vpmtmr_detach_ioport(vpmtmr);
		VERIFY3P(err, ==, 0);
	}
	err = vm_ioport_attach(vm, ioport, vpmtmr_handler, vpmtmr,
	    &vpmtmr->io_cookie);
	if (err == 0) {
		vpmtmr->io_port = ioport;
	}

	return (err);
}

int
vpmtmr_handler(void *arg, bool in, uint16_t port, uint8_t bytes, uint32_t *val)
{
	struct vpmtmr *vpmtmr = arg;

	if (!in || bytes != 4)
		return (-1);

	/*
	 * No locking needed because 'base_time' is written only during
	 * initialization.
	 */
	const hrtime_t delta = gethrtime() - vpmtmr->base_time;
	ASSERT3S(delta, >=, 0);

	*val = hrt_freq_count(delta, PMTMR_FREQ);

	return (0);
}

static int
vpmtmr_data_read(void *datap, const vmm_data_req_t *req)
{
	VERIFY3U(req->vdr_class, ==, VDC_PM_TIMER);
	VERIFY3U(req->vdr_version, ==, 1);
	VERIFY3U(req->vdr_len, >=, sizeof (struct vdi_pm_timer_v1));

	struct vpmtmr *vpmtmr = datap;
	struct vdi_pm_timer_v1 *out = req->vdr_data;

	out->vpt_time_base = vm_normalize_hrtime(vpmtmr->vm, vpmtmr->base_time);
	out->vpt_ioport = vpmtmr->io_port;

	return (0);
}

static int
vpmtmr_data_write(void *datap, const vmm_data_req_t *req)
{
	VERIFY3U(req->vdr_class, ==, VDC_PM_TIMER);
	VERIFY3U(req->vdr_version, ==, 1);
	VERIFY3U(req->vdr_len, >=, sizeof (struct vdi_pm_timer_v1));

	struct vpmtmr *vpmtmr = datap;
	const struct vdi_pm_timer_v1 *src = req->vdr_data;

	vpmtmr->base_time =
	    vm_denormalize_hrtime(vpmtmr->vm, src->vpt_time_base);

	return (0);
}

static const vmm_data_version_entry_t pm_timer_v1 = {
	.vdve_class = VDC_PM_TIMER,
	.vdve_version = 1,
	.vdve_len_expect = sizeof (struct vdi_pm_timer_v1),
	.vdve_readf = vpmtmr_data_read,
	.vdve_writef = vpmtmr_data_write,
};
VMM_DATA_VERSION(pm_timer_v1);
