/*
 * Copyright (c) 2014,2016 Microsoft Corp.
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

/*
 * Copyright (c) 2017 by Delphix. All rights reserved.
 */

#include <sys/conf.h>
#include <sys/sunddi.h>
#include <sys/devops.h>
#include <sys/cmn_err.h>

#include <sys/param.h>
#include <sys/systm.h>

#include <sys/hyperv.h>
#include <sys/vmbus.h>
#include "vmbus_icvar.h"
#include "vmbus_icreg.h"

#define	VMBUS_HEARTBEAT_FWVER_MAJOR	3
#define	VMBUS_HEARTBEAT_FWVER		\
	VMBUS_IC_VERSION(VMBUS_HEARTBEAT_FWVER_MAJOR, 0)

#define	VMBUS_HEARTBEAT_MSGVER_MAJOR	3
#define	VMBUS_HEARTBEAT_MSGVER		\
	VMBUS_IC_VERSION(VMBUS_HEARTBEAT_MSGVER_MAJOR, 0)

const struct vmbus_ic_desc vmbus_heartbeat_descs[] = {
	{
		.ic_guid = { .hv_guid = {
		    0x39, 0x4f, 0x16, 0x57, 0x15, 0x91, 0x78, 0x4e,
		    0xab, 0x55, 0x38, 0x2f, 0x3b, 0xd5, 0x42, 0x2d} },
		.ic_desc = "Hyper-V Heartbeat"
	},
	VMBUS_IC_DESC_END
};

static void *vmbus_heartbeat_state;

static void
vmbus_heartbeat_cb(struct vmbus_channel *chan, void *xsc)
{
	struct vmbus_ic_softc *sc = xsc;
	struct vmbus_icmsg_hdr *hdr;
	int dlen, error = 0;
	uint64_t xactid;
	void *data;

	/*
	 * Receive request.
	 */
	data = sc->ic_buf;
	dlen = sc->ic_buflen;
	error = vmbus_chan_recv(chan, data, &dlen, &xactid);
	/*
	 * icbuf must be large enough.
	 */
	ASSERT3S(error, !=, ENOBUFS);
	if (error)
		return;

	if (dlen < sizeof (*hdr)) {
		dev_err(sc->ic_dev, CE_WARN, "invalid data len %d", dlen);
		return;
	}
	hdr = data;

	/*
	 * Update request, which will be echoed back as response.
	 */
	switch (hdr->ic_type) {
	case VMBUS_ICMSG_TYPE_NEGOTIATE:
		error = vmbus_ic_negomsg(sc, data, &dlen,
		    VMBUS_HEARTBEAT_FWVER, VMBUS_HEARTBEAT_MSGVER);
		if (error != 0) {
			dev_err(sc->ic_dev, CE_WARN,
			    "vmbus_ic_negomsg failed, error: %d, data: 0x%p,"
			    " dlen: %d", error, data, dlen);
			return;
		}
		break;

	case VMBUS_ICMSG_TYPE_HEARTBEAT:
		/* Only ic_seq is a must */
		if (dlen < VMBUS_ICMSG_HEARTBEAT_SIZE_MIN) {
			dev_err(sc->ic_dev, CE_WARN,
			    "invalid heartbeat len %d", dlen);
			return;
		}
		((struct vmbus_icmsg_heartbeat *)data)->ic_seq++;
		break;

	default:
		dev_err(sc->ic_dev, CE_WARN, "got 0x%08x icmsg",
		    hdr->ic_type);
		break;
	}

	/*
	 * Send response by echoing the request back.
	 */
	(void) vmbus_ic_sendresp(sc, chan, data, dlen, xactid);
}

static int
vmbus_heartbeat_attach(dev_info_t *dev, ddi_attach_cmd_t cmd)
{
	int err;
	struct vmbus_ic_softc *sc;
	int instance = ddi_get_instance(dev);

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if ((err = ddi_soft_state_zalloc(vmbus_heartbeat_state, instance)) !=
	    DDI_SUCCESS)
		return (err);

	sc = ddi_get_soft_state(vmbus_heartbeat_state, instance);
	err = vmbus_ic_attach(dev, vmbus_heartbeat_cb, sc);
	if (err != 0)
		ddi_soft_state_free(vmbus_heartbeat_state, instance);

	return (err);
}

static int
vmbus_heartbeat_detach(dev_info_t *dev, ddi_detach_cmd_t cmd)
{
	int instance = ddi_get_instance(dev);

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	int err = vmbus_ic_detach(dev,
	    ddi_get_soft_state(vmbus_heartbeat_state, instance));
	if (err == 0)
		ddi_soft_state_free(vmbus_heartbeat_state, instance);
	return (err);
}

static struct cb_ops vmbus_heartbeat_cb_ops = {
	.cb_open =	nulldev,
	.cb_close =	nulldev,
	.cb_strategy =	nodev,
	.cb_print =	nodev,
	.cb_dump =	nodev,
	.cb_read =	nodev,
	.cb_write =	nodev,
	.cb_ioctl =	nodev,
	.cb_devmap =	nodev,
	.cb_mmap =	nodev,
	.cb_segmap =	nodev,
	.cb_chpoll =	nochpoll,
	.cb_prop_op =	ddi_prop_op,
	.cb_str =	NULL,
	.cb_flag =	D_NEW | D_MP
};

static struct dev_ops vmbus_heartbeat_dev_ops = {
	.devo_rev =		DEVO_REV,
	.devo_refcnt =		0,
	.devo_getinfo =		ddi_getinfo_1to1,
	.devo_identify =	nulldev,
	.devo_probe =		nulldev,
	.devo_attach =		vmbus_heartbeat_attach,
	.devo_detach =		vmbus_heartbeat_detach,
	.devo_reset =		nodev,
	.devo_cb_ops =		&vmbus_heartbeat_cb_ops,
	.devo_bus_ops =		NULL,
	.devo_power =		NULL,
	.devo_quiesce =		ddi_quiesce_not_needed
};

extern struct mod_ops mod_driverops;

static struct modldrv vmbus_heartbeat_modldrv = {
	&mod_driverops,
	"Hyper-V Heartbeat Driver",
	&vmbus_heartbeat_dev_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&vmbus_heartbeat_modldrv,
	NULL
};

int
_init(void)
{
	int error;

	if ((error = ddi_soft_state_init(&vmbus_heartbeat_state,
	    sizeof (struct vmbus_ic_softc), 0)) != 0)
		return (error);

	if ((error = mod_install(&modlinkage)) != 0)
		ddi_soft_state_fini(&vmbus_heartbeat_state);
	return (error);
}

int
_fini(void)
{
	int error;

	if ((error = mod_remove(&modlinkage)) == 0)
		ddi_soft_state_fini(&vmbus_heartbeat_state);
	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
