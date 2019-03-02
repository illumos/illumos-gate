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
#include <sys/uadmin.h>

#include <sys/hyperv.h>
#include <sys/vmbus.h>
#include "vmbus_icreg.h"
#include "vmbus_icvar.h"

#define	VMBUS_SHUTDOWN_FWVER_MAJOR	3
#define	VMBUS_SHUTDOWN_FWVER		\
	VMBUS_IC_VERSION(VMBUS_SHUTDOWN_FWVER_MAJOR, 0)

#define	VMBUS_SHUTDOWN_MSGVER_MAJOR	3
#define	VMBUS_SHUTDOWN_MSGVER		\
	VMBUS_IC_VERSION(VMBUS_SHUTDOWN_MSGVER_MAJOR, 0)

const struct vmbus_ic_desc vmbus_shutdown_descs[] = {
	{
		.ic_guid = { .hv_guid = {
		    0x31, 0x60, 0x0b, 0x0e, 0x13, 0x52, 0x34, 0x49,
		    0x81, 0x8b, 0x38, 0xd9, 0x0c, 0xed, 0x39, 0xdb } },
		.ic_desc = "Hyper-V Shutdown"
	},
	VMBUS_IC_DESC_END
};

static void *vmbus_shutdown_state;
#define	SHUTDOWN_TIMEOUT_SECS	(60 * 5)

/* ARGSUSED */
static void
vmbus_poweroff(void *arg)
{
	(void) kadmin(A_SHUTDOWN, AD_POWEROFF, NULL, kcred);
}

static void
vmbus_shutdown_cb(struct vmbus_channel *chan, void *xsc)
{
	struct vmbus_ic_softc *sc = xsc;
	struct vmbus_icmsg_hdr *hdr;
	struct vmbus_icmsg_shutdown *msg;
	int dlen, error = 0, do_shutdown = 0;
	uint64_t xactid;
	void *data;
	proc_t *initpp;

	/*
	 * Receive request.
	 */
	data = sc->ic_buf;
	dlen = sc->ic_buflen;
	error = vmbus_chan_recv(chan, data, &dlen, &xactid);
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
		    VMBUS_SHUTDOWN_FWVER, VMBUS_SHUTDOWN_MSGVER);
		if (error)
			return;
		break;

	case VMBUS_ICMSG_TYPE_SHUTDOWN:
		if (dlen < VMBUS_ICMSG_SHUTDOWN_SIZE_MIN) {
			dev_err(sc->ic_dev, CE_WARN,
			    "invalid shutdown len %d", dlen);
			return;
		}
		msg = data;

		/* XXX ic_flags definition? */
		if (msg->ic_haltflags == 0 || msg->ic_haltflags == 1) {
			dev_err(sc->ic_dev, CE_NOTE, "shutdown requested");
			hdr->ic_status = VMBUS_ICMSG_STATUS_OK;
			do_shutdown = 1;
		} else {
			dev_err(sc->ic_dev, CE_WARN, "unknown shutdown flags "
			    "0x%08x", msg->ic_haltflags);
			hdr->ic_status = VMBUS_ICMSG_STATUS_FAIL;
		}
		break;

	default:
		dev_err(sc->ic_dev, CE_NOTE, "got 0x%08x icmsg",
		    hdr->ic_type);
		break;
	}

	/*
	 * Send response by echoing the request back.
	 */
	(void) vmbus_ic_sendresp(sc, chan, data, dlen, xactid);

	if (do_shutdown) {
		/*
		 * If we're still booting and init(1) isn't set up yet,
		 * simply halt.
		 */
		mutex_enter(&pidlock);
		initpp = prfind(P_INITPID);
		mutex_exit(&pidlock);
		if (initpp == NULL) {
			extern void halt(char *);
			halt("Power off the System");
		}

		/*
		 * Graceful shutdown with inittab and all getting involved
		 */
		psignal(initpp, SIGPWR);

		(void) timeout(vmbus_poweroff, NULL,
		    SHUTDOWN_TIMEOUT_SECS * drv_usectohz(MICROSEC));
	}
}

static int
vmbus_shutdown_attach(dev_info_t *dev, ddi_attach_cmd_t cmd)
{
	int err;
	struct vmbus_ic_softc *sc;
	int instance = ddi_get_instance(dev);

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if ((err = ddi_soft_state_zalloc(vmbus_shutdown_state, instance)) !=
	    DDI_SUCCESS)
		return (err);

	sc = ddi_get_soft_state(vmbus_shutdown_state, instance);
	err = vmbus_ic_attach(dev, vmbus_shutdown_cb, sc);
	if (err != 0)
		ddi_soft_state_free(vmbus_shutdown_state, instance);

	return (err);
}

static int
vmbus_shutdown_detach(dev_info_t *dev, ddi_detach_cmd_t cmd)
{
	int instance = ddi_get_instance(dev);

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	int err = vmbus_ic_detach(dev,
	    ddi_get_soft_state(vmbus_shutdown_state, instance));
	if (err == 0)
		ddi_soft_state_free(vmbus_shutdown_state, instance);
	return (err);
}

static struct cb_ops vmbus_shutdown_cb_ops = {
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

static struct dev_ops vmbus_shutdown_dev_ops = {
	.devo_rev =		DEVO_REV,
	.devo_refcnt =		0,
	.devo_getinfo =		ddi_getinfo_1to1,
	.devo_identify =	nulldev,
	.devo_probe =		nulldev,
	.devo_attach =		vmbus_shutdown_attach,
	.devo_detach =		vmbus_shutdown_detach,
	.devo_reset =		nodev,
	.devo_cb_ops =		&vmbus_shutdown_cb_ops,
	.devo_bus_ops =		NULL,
	.devo_power =		NULL,
	.devo_quiesce =		ddi_quiesce_not_needed
};

extern struct mod_ops mod_driverops;

static struct modldrv vmbus_shutdown_modldrv = {
	&mod_driverops,
	"Hyper-V Shutdown Driver",
	&vmbus_shutdown_dev_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&vmbus_shutdown_modldrv,
	NULL
};

int
_init(void)
{
	int error;

	if ((error = ddi_soft_state_init(&vmbus_shutdown_state,
	    sizeof (struct vmbus_ic_softc), 0)) != 0)
		return (error);

	if ((error = mod_install(&modlinkage)) != 0)
		ddi_soft_state_fini(&vmbus_shutdown_state);
	return (error);
}

int
_fini(void)
{
	int error;

	if ((error = mod_remove(&modlinkage)) == 0)
		ddi_soft_state_fini(&vmbus_shutdown_state);
	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
