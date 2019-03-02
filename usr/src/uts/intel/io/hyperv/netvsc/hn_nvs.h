/*
 * Copyright (c) 2009-2012,2016 Microsoft Corp.
 * Copyright (c) 2010-2012 Citrix Inc.
 * Copyright (c) 2012 NetApp Inc.
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

#ifndef _HN_NVS_H
#define	_HN_NVS_H

#include "if_hnreg.h"

#include <sys/vmbus.h>

struct hn_nvs_sendctx;
struct vmbus_channel;
struct hn_softc;

typedef void (*hn_nvs_sent_t)(struct hn_nvs_sendctx *, struct hn_softc *,
    struct vmbus_channel *, const void *, int);

struct hn_nvs_sendctx {
	hn_nvs_sent_t	hn_cb;
	void		*hn_cbarg;
};

#define	HN_NVS_SENDCTX_INITIALIZER(cb, cbarg)	\
{						\
	.hn_cb		= cb,			\
	.hn_cbarg	= cbarg			\
}

static inline void
hn_nvs_sendctx_init(struct hn_nvs_sendctx *sndc, hn_nvs_sent_t cb, void *cbarg)
{

	sndc->hn_cb = cb;
	sndc->hn_cbarg = cbarg;
}

static inline int
hn_nvs_send(struct vmbus_channel *chan, uint16_t flags,
    void *nvs_msg, int nvs_msglen, struct hn_nvs_sendctx *sndc)
{

	return (vmbus_chan_send(chan, VMBUS_CHANPKT_TYPE_INBAND, flags,
	    nvs_msg, nvs_msglen, (uint64_t)(uintptr_t)sndc));
}

static inline int
hn_nvs_send_sglist(struct vmbus_channel *chan, struct vmbus_gpa sg[], int sglen,
    void *nvs_msg, int nvs_msglen, struct hn_nvs_sendctx *sndc)
{

	return (vmbus_chan_send_sglist(chan, sg, sglen, nvs_msg, nvs_msglen,
	    (uint64_t)(uintptr_t)sndc));
}

int		hn_nvs_attach(struct hn_softc *sc, int mtu);
void		hn_nvs_detach(struct hn_softc *sc);
int		hn_nvs_alloc_subchans(struct hn_softc *sc, int *nsubch);
void		hn_nvs_sent_xact(struct hn_nvs_sendctx *sndc,
		    struct hn_softc *sc, struct vmbus_channel *chan,
		    const void *data, int dlen);
int		hn_nvs_send_rndis_ctrl(struct vmbus_channel *chan,
		    struct hn_nvs_sendctx *sndc, struct vmbus_gpa *gpa,
		    int gpa_cnt);
int		hn_nvs_send_rndis_sglist(struct vmbus_channel *chan,
		    uint32_t rndis_mtype, struct hn_nvs_sendctx *sndc,
		    struct vmbus_gpa *gpa, int gpa_cnt);

extern struct hn_nvs_sendctx	hn_nvs_sendctx_none;

#endif /* !_HN_NVS_H */
