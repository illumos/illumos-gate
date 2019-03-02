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
#include <sys/time.h>
#include <sys/x86_archext.h>
#include <sys/reboot.h>

#include <sys/hyperv.h>
#include <sys/vmbus.h>
#include "vmbus_icreg.h"
#include "vmbus_icvar.h"

#define	VMBUS_TIMESYNC_FWVER_MAJOR	3
#define	VMBUS_TIMESYNC_FWVER		\
	VMBUS_IC_VERSION(VMBUS_TIMESYNC_FWVER_MAJOR, 0)

#define	VMBUS_TIMESYNC_MSGVER_MAJOR	4
#define	VMBUS_TIMESYNC_MSGVER		\
	VMBUS_IC_VERSION(VMBUS_TIMESYNC_MSGVER_MAJOR, 0)

#define	VMBUS_TIMESYNC_MSGVER4(sc)	\
	VMBUS_ICVER_LE(VMBUS_IC_VERSION(4, 0), (sc)->ic_msgver)

#define	VMBUS_TIMESYNC_DORTT(sc)       \
	(VMBUS_TIMESYNC_MSGVER4((sc)) && \
	(hyperv_features & CPUID_HV_MSR_TIME_REFCNT))

const struct vmbus_ic_desc vmbus_timesync_descs[] = {
	{
		.ic_guid = { .hv_guid = {
		    0x30, 0xe6, 0x27, 0x95, 0xae, 0xd0, 0x7b, 0x49,
		    0xad, 0xce, 0xe8, 0x0a, 0xb0, 0x17, 0x5c, 0xaf } },
		.ic_desc = "Hyper-V Timesync"
	},
	VMBUS_IC_DESC_END
};

static void *vmbus_timesync_state;

/*
 * Ignore the sync request.
 */
int vmbus_ts_ignore_sync = 0;

/*
 * Trigger a sample sync when drift exceeds this threshold (ms).
 * Ignore the sample request when set to 0.
 */
int vmbus_ts_sample_thresh = 100;

/*
 * Increase sample request verbosity
 */
boolean_t vmbus_ts_sample_verbose = B_FALSE;

static void
vmbus_timesync(struct vmbus_ic_softc *sc, uint64_t hvtime, uint64_t sent_tc,
    uint8_t tsflags)
{
	hrtime_t hv_ns, vm_ns;
	uint64_t rtt = 0;
	timestruc_t now;

	if (VMBUS_TIMESYNC_DORTT(sc))
		rtt = rdmsr(MSR_HV_TIME_REF_COUNT) - sent_tc;

	hv_ns = (hvtime - VMBUS_ICMSG_TS_BASE + rtt) * HYPERV_TIMER_NS_FACTOR;
	gethrestime(&now);
	vm_ns = now.tv_sec * NANOSEC + now.tv_nsec;

	if ((tsflags & VMBUS_ICMSG_TS_FLAG_SYNC) && !vmbus_ts_ignore_sync) {
		timestruc_t hv_ts;

		if (boothowto & RB_VERBOSE) {
			dev_err(sc->ic_dev, CE_NOTE, "apply sync request, "
			    "hv: %lld, vm: %lld", hv_ns, vm_ns);
		}
		hv_ts.tv_sec = hv_ns / NANOSEC;
		hv_ts.tv_nsec = hv_ns % NANOSEC;
		mutex_enter(&tod_lock);
		tod_set(hv_ts);
		set_hrestime(&hv_ts);
		mutex_exit(&tod_lock);
		/* Done! */
		return;
	}

	if ((tsflags & VMBUS_ICMSG_TS_FLAG_SAMPLE) &&
	    vmbus_ts_sample_thresh >= 0) {
		int64_t diff;

		if (vmbus_ts_sample_verbose) {
			dev_err(sc->ic_dev, CE_NOTE, "sample request, "
			    "hv: %lld, vm: %lld", hv_ns, vm_ns);
		}

		if (hv_ns > vm_ns)
			diff = hv_ns - vm_ns;
		else
			diff = vm_ns - hv_ns;
		/* nanosec -> millisec */
		diff /= 1000000;

		if (diff > vmbus_ts_sample_thresh) {
			timestruc_t hv_ts;

			if (boothowto & RB_VERBOSE) {
				dev_err(sc->ic_dev, CE_NOTE,
				    "apply sample request, hv: %lld, "
				    "vm: %lld", hv_ns, vm_ns);
			}
			hv_ts.tv_sec = hv_ns / NANOSEC;
			hv_ts.tv_nsec = hv_ns % NANOSEC;
			mutex_enter(&tod_lock);
			tod_set(hv_ts);
			set_hrestime(&hv_ts);
			mutex_exit(&tod_lock);
		}
		/* Done */
		return;
	}
}

static void
vmbus_timesync_cb(struct vmbus_channel *chan, void *xsc)
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
	 * icbuf must be large enough
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
		    VMBUS_TIMESYNC_FWVER, VMBUS_TIMESYNC_MSGVER);
		if (error)
			return;
		if (VMBUS_TIMESYNC_DORTT(sc))
			dev_err(sc->ic_dev, CE_WARN, "RTT");
		break;

	case VMBUS_ICMSG_TYPE_TIMESYNC:
		if (VMBUS_TIMESYNC_MSGVER4(sc)) {
			const struct vmbus_icmsg_timesync4 *msg4;

			if (dlen < sizeof (*msg4)) {
				dev_err(sc->ic_dev, CE_WARN,
				    "invalid timesync4 len %d", dlen);
				return;
			}
			msg4 = data;
			vmbus_timesync(sc, msg4->ic_hvtime, msg4->ic_sent_tc,
			    msg4->ic_tsflags);
		} else {
			const struct vmbus_icmsg_timesync *msg;

			if (dlen < sizeof (*msg)) {
				dev_err(sc->ic_dev, CE_WARN, "invalid timesync "
				    "len %d", dlen);
				return;
			}
			msg = data;
			vmbus_timesync(sc, msg->ic_hvtime, 0, msg->ic_tsflags);
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
}

static int
vmbus_timesync_attach(dev_info_t *dev, ddi_attach_cmd_t cmd)
{
	int err;
	int instance = ddi_get_instance(dev);

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if ((err = ddi_soft_state_zalloc(vmbus_timesync_state, instance)) !=
	    DDI_SUCCESS)
		return (err);

	err = vmbus_ic_attach(dev, vmbus_timesync_cb,
	    ddi_get_soft_state(vmbus_timesync_state, instance));
	if (err != 0)
		ddi_soft_state_free(vmbus_timesync_state, instance);

	return (err);
}

static int
vmbus_timesync_detach(dev_info_t *dev, ddi_detach_cmd_t cmd)
{
	int instance = ddi_get_instance(dev);

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	int err = vmbus_ic_detach(dev,
	    ddi_get_soft_state(vmbus_timesync_state, instance));
	if (err == 0)
		ddi_soft_state_free(vmbus_timesync_state, instance);
	return (err);
}

static struct cb_ops vmbus_timesync_cb_ops = {
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

static struct dev_ops vmbus_timesync_dev_ops = {
	.devo_rev =		DEVO_REV,
	.devo_refcnt =		0,
	.devo_getinfo =		ddi_getinfo_1to1,
	.devo_identify =	nulldev,
	.devo_probe =		nulldev,
	.devo_attach =		vmbus_timesync_attach,
	.devo_detach =		vmbus_timesync_detach,
	.devo_reset =		nodev,
	.devo_cb_ops =		&vmbus_timesync_cb_ops,
	.devo_bus_ops =		NULL,
	.devo_power =		NULL,
	.devo_quiesce =		ddi_quiesce_not_needed
};

extern struct mod_ops mod_driverops;

static struct modldrv vmbus_timesync_modldrv = {
	&mod_driverops,
	"Hyper-V Timesync Driver",
	&vmbus_timesync_dev_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&vmbus_timesync_modldrv,
	NULL
};

int
_init(void)
{
	int error;

	if ((error = ddi_soft_state_init(&vmbus_timesync_state,
	    sizeof (struct vmbus_ic_softc), 0)) != 0)
		return (error);

	if ((error = mod_install(&modlinkage)) != 0)
		ddi_soft_state_fini(&vmbus_timesync_state);
	return (error);
}

int
_fini(void)
{
	int error;

	if ((error = mod_remove(&modlinkage)) == 0)
		ddi_soft_state_fini(&vmbus_timesync_state);
	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
