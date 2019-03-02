/*
 * Copyright (c) 2016 Microsoft Corp.
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
 *
 * $FreeBSD$
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

/*
 * Copyright (c) 2017 by Delphix. All rights reserved.
 */

#ifndef _VMBUS_CHANVAR_H_
#define	_VMBUS_CHANVAR_H_

#include <sys/param.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/taskq.h>

#include <sys/hyperv.h>
#include <sys/hyperv_busdma.h>
#include <sys/vmbus.h>
#include "vmbus_brvar.h"


struct vmbus_channel {
	/*
	 * NOTE:
	 * Fields before ch_txbr are only accessed on this channel's
	 * target CPU.
	 */
	uint32_t			ch_flags;	/* VMBUS_CHAN_FLAG_ */

	/*
	 * RX bufring; immediately following ch_txbr.
	 */
	struct vmbus_rxbr		ch_rxbr;

	ddi_taskq_t			*ch_tq;
	task_func_t			*ch_tqent_func;
	/* taskq_ent_t			ch_task; */
	vmbus_chan_callback_t		ch_cb;
	void				*ch_cbarg;

	/*
	 * TX bufring; at the beginning of ch_bufring.
	 *
	 * NOTE:
	 * Put TX bufring and the following MNF/evtflag to a new
	 * cacheline, since they will be accessed on all CPUs by
	 * locking ch_txbr first.
	 *
	 * XXX
	 * TX bufring and following MNF/evtflags do _not_ fit in
	 * one 64B cacheline.
	 */
	struct vmbus_txbr		ch_txbr __aligned(64);
	uint32_t			ch_txflags;	/* VMBUS_CHAN_TXF_ */

	/*
	 * These are based on the vmbus_chanmsg_choffer.chm_montrig.
	 * Save it here for easy access.
	 */
	uint32_t			ch_montrig_mask; /* MNF trig mask */
	volatile uint32_t		*ch_montrig;	/* MNF trigger loc. */

	/*
	 * These are based on the vmbus_chanmsg_choffer.chm_chanid.
	 * Save it here for easy access.
	 */
	ulong_t				ch_evtflag_mask; /* event flag */
	volatile ulong_t		*ch_evtflag;	/* event flag loc. */

	/*
	 * Rarely used fields.
	 */

	struct hyperv_mon_param		*ch_monprm;
	struct hyperv_dma		ch_monprm_dma;

	uint32_t			ch_id;		/* channel id */
	dev_info_t			*ch_dev;
	struct vmbus_softc		*ch_vmbus;

	int				ch_cpuid;	/* owner cpu */
	/*
	 * Virtual cpuid for ch_cpuid; it is used to communicate cpuid
	 * related information w/ Hyper-V.  If MSR_HV_VP_INDEX does not
	 * exist, ch_vcpuid will always be 0 for compatibility.
	 */
	uint32_t			ch_vcpuid;

	/*
	 * If this is a primary channel, ch_subchan* fields
	 * contain sub-channels belonging to this primary
	 * channel.
	 */
	kmutex_t			ch_subchan_lock;
	kcondvar_t			ch_subchan_cv;
	TAILQ_HEAD(, vmbus_channel)	ch_subchans;
	int				ch_subchan_cnt;

	/* If this is a sub-channel */
	TAILQ_ENTRY(vmbus_channel)	ch_sublink;	/* sub-channel link */
	struct vmbus_channel		*ch_prichan;	/* owner primary chan */

	void				*ch_bufring;	/* TX+RX bufrings */
	struct hyperv_dma		ch_bufring_dma;
	uint32_t			ch_bufring_gpadl;

	/* run in ch_mgmt_tq */
	task_func_t			*ch_attach_task;
	task_func_t			*ch_detach_task;
	ddi_taskq_t			*ch_mgmt_tq;

	/* If this is a primary channel */
	TAILQ_ENTRY(vmbus_channel)	ch_prilink;	/* primary chan link */

	TAILQ_ENTRY(vmbus_channel)	ch_link;	/* channel link */
	uint32_t			ch_subidx;	/* subchan index */
	volatile uint32_t		ch_stflags;	/* atomic-op */
							/* VMBUS_CHAN_ST_ */
	struct hyperv_guid		ch_guid_type;
	struct hyperv_guid		ch_guid_inst;

	kmutex_t			ch_orphan_lock;
	struct vmbus_xact_ctx		*ch_orphan_xact;

	uint32_t			ch_refs;

} __aligned(64);

#define	VMBUS_CHAN_ISPRIMARY(chan)	((chan)->ch_subidx == 0)

/*
 * If this flag is set, this channel's interrupt will be masked in ISR,
 * and the RX bufring will be drained before this channel's interrupt is
 * unmasked.
 *
 * This flag is turned on by default.  Drivers can turn it off according
 * to their own requirement.
 */
#define	VMBUS_CHAN_FLAG_BATCHREAD	0x0002

#define	VMBUS_CHAN_TXF_HASMNF		0x0001

#define	VMBUS_CHAN_ST_OPENED_SHIFT	0
#define	VMBUS_CHAN_ST_ONPRIL_SHIFT	1
#define	VMBUS_CHAN_ST_ONSUBL_SHIFT	2
#define	VMBUS_CHAN_ST_ONLIST_SHIFT	3
#define	VMBUS_CHAN_ST_REVOKED_SHIFT	4	/* sticky */
#define	VMBUS_CHAN_ST_OPENED		(1 << VMBUS_CHAN_ST_OPENED_SHIFT)
#define	VMBUS_CHAN_ST_ONPRIL		(1 << VMBUS_CHAN_ST_ONPRIL_SHIFT)
#define	VMBUS_CHAN_ST_ONSUBL		(1 << VMBUS_CHAN_ST_ONSUBL_SHIFT)
#define	VMBUS_CHAN_ST_ONLIST		(1 << VMBUS_CHAN_ST_ONLIST_SHIFT)
#define	VMBUS_CHAN_ST_REVOKED		(1 << VMBUS_CHAN_ST_REVOKED_SHIFT)

struct vmbus_softc;
struct vmbus_message;

void		vmbus_event_proc(struct vmbus_softc *, int);
void		vmbus_event_proc_compat(struct vmbus_softc *, int);
void		vmbus_chan_msgproc(struct vmbus_softc *,
		    const struct vmbus_message *);
void		vmbus_chan_destroy_all(struct vmbus_softc *);

#endif	/* !_VMBUS_CHANVAR_H_ */
